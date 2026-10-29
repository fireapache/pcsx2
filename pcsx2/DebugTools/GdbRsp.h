// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

// The GDB remote serial protocol for the EE.
//
// Session is the protocol itself, without a transport: bytes from gdb go in,
// bytes for gdb come out through a callback. Server carries one Session at a
// time over a loopback TCP socket. Neither touches emulator state - that is
// the Target, implemented for the running VM in GdbServer.cpp - so the
// protocol can be unit tested on its own (tests/ctest/core/gdbrsp_tests.cpp).

#include "common/Pcsx2Types.h"

#include <atomic>
#include <functional>
#include <string>
#include <string_view>

namespace GdbRsp
{
	enum class StopReason
	{
		Interrupt, // gdb asked (Ctrl+C), or the emulator was paused from its UI
		Breakpoint, // also the end of a single step
		Watchpoint,
		Fault, // an access to unmapped memory - reported as SIGSEGV
	};

	enum class WatchKind
	{
		Write,
		Read,
		Access,
	};

	struct Stop
	{
		StopReason reason = StopReason::Interrupt;
		WatchKind watch_kind = WatchKind::Write;
		u32 data_address = 0; // the watched or faulting access
		// Shown in the debugger's console before the stop (an O packet), e.g.
		// what a fault touched. Empty: nothing is shown.
		std::string message;
	};

	// The registers gdb sees, in its mips numbering: r0-r31, status, lo, hi,
	// badvaddr, cause, pc, f0-f31, fcsr, fir. EE programs are n32, so the GPRs
	// are the low 64 bits of the 128-bit registers.
	struct Registers
	{
		u64 gpr[32] = {};
		u32 status = 0;
		u64 lo = 0;
		u64 hi = 0;
		u32 badvaddr = 0;
		u32 cause = 0;
		u64 pc = 0;
		u32 fpr[32] = {};
		u32 fcsr = 0;
		u32 fir = 0;
	};

	// The machine being debugged.
	class Target
	{
	public:
		virtual ~Target() = default;

		// There is a machine to debug. The server only listens while this holds.
		virtual bool IsAlive() = 0;
		virtual bool IsHalted() = 0;
		// Asynchronous: IsHalted() turns true some time later.
		virtual void RequestHalt() = 0;
		// Both return once the machine runs. A step halts again after one
		// instruction (a branch together with its delay slot) as a Breakpoint.
		virtual void Resume() = 0;
		virtual void Step() = 0;
		// Why the machine halted; called once per stop.
		virtual Stop TakeStop() = 0;

		virtual void ReadRegisters(Registers& regs) = 0;
		virtual void WriteRegisters(const Registers& regs) = 0;
		virtual bool ReadMemory(u32 address, void* dest, u32 size) = 0;
		virtual bool WriteMemory(u32 address, const void* src, u32 size) = 0;
		virtual bool SetBreakpoint(u32 address, bool set) = 0;
		virtual bool SetWatchpoint(u32 address, u32 size, WatchKind kind, bool set) = 0;
		// A debugger connected; the machine may still be running.
		virtual void Attached() {}
		// The debugger went away: drop every breakpoint and watchpoint it set.
		virtual void ClearAll() = 0;
	};

	class Session
	{
	public:
		using SendFunction = std::function<void(std::string_view)>;

		Session(Target& target, SendFunction send);

		// A debugger connected and the machine is halted: take the stop gdb
		// will ask about first.
		void Begin();
		// Bytes from gdb. False once the session is over (detach or kill).
		bool Receive(std::string_view bytes);
		// While the machine runs: reports the stop once it has halted.
		void Poll();
		// The machine is gone (the VM shut down).
		void Exited();

		bool IsRunning() const { return m_running; }

	private:
		bool HandlePacket(std::string_view packet);
		void SendPacket(std::string_view payload);
		std::string StopReply() const;

		Target& m_target;
		SendFunction m_send;
		std::string m_rx; // received, not yet consumed
		Stop m_last_stop;
		bool m_running = false;
		bool m_no_ack = false;
	};

	class Server
	{
	public:
		using LogFunction = std::function<void(const std::string&)>;

		Server(Target& target, LogFunction log);

		// Listens on 127.0.0.1:port and serves one debugger at a time until
		// RequestStop(). Blocking: give it a thread of its own.
		void Run(u16 port);
		void RequestStop() { m_stop_requested.store(true, std::memory_order_release); }
		bool HasClient() const { return m_has_client.load(std::memory_order_acquire); }

	private:
		bool Alive() const;
		void Serve(intptr_t client);

		Target& m_target;
		LogFunction m_log;
		std::atomic<bool> m_stop_requested{false};
		std::atomic<bool> m_has_client{false};
	};

	// Exposed for the tests.
	std::string EncodeRegisters(const Registers& regs);
	bool DecodeRegisters(std::string_view hex, Registers& regs);
} // namespace GdbRsp
