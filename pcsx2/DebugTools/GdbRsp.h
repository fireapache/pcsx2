// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

// GDB remote serial protocol for the EE: packet framing, the register layout
// and command dispatch, served on a loopback TCP socket.
//
// Deliberately free of PCSX2 headers: tests/gdbrsp drives this file with the
// real mips64r5900el-ps2-elf-gdb and a fake target. GdbServer.cpp is the
// emulator side (the EE behind the Target interface, lifecycle, hooks).

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace GdbRsp
{
	enum class StopReason
	{
		Interrupt, // gdb asked (Ctrl+C), or the emulator was paused by hand
		Breakpoint,
		Watchpoint,
		Fault, // an access to unmapped memory (vtlb miss) - reported as SIGSEGV
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
		uint32_t data_address = 0; // the watched access, or the faulting one
	};

	// The register file gdb sees, in its mips numbering. The ELF is n32, so
	// GPRs are 64 bits (the low half of the EE's 128); on the wire every
	// register is 8 bytes (see GdbRsp.cpp).
	struct Registers
	{
		uint64_t gpr[32] = {};
		uint32_t status = 0;
		uint64_t lo = 0;
		uint64_t hi = 0;
		uint32_t badvaddr = 0;
		uint32_t cause = 0;
		uint64_t pc = 0;
		uint32_t fpr[32] = {}; // single precision: the EE FPU has no doubles
		uint32_t fcsr = 0;
		uint32_t fir = 0;
	};

	class Target
	{
	public:
		virtual ~Target() = default;

		// A machine exists to debug. The server only listens while this is true,
		// so a client that connects early is refused instead of timing out.
		virtual bool IsAlive() = 0;
		virtual bool IsHalted() = 0;
		// Asynchronous: IsHalted() turns true some time later.
		virtual void RequestHalt() = 0;
		// Returns once the machine runs (IsHalted() is false).
		virtual void Resume() = 0;
		// Runs one instruction (a branch together with its delay slot), then
		// halts again with a Breakpoint stop. Returns once the machine runs.
		virtual void Step() = 0;
		// Why the machine is halted; called once per stop.
		virtual Stop TakeStop() = 0;

		virtual void ReadRegisters(Registers& regs) = 0;
		virtual void WriteRegisters(const Registers& regs) = 0;
		virtual bool ReadMemory(uint32_t address, void* dest, uint32_t size) = 0;
		virtual bool WriteMemory(uint32_t address, const void* src, uint32_t size) = 0;
		virtual bool SetBreakpoint(uint32_t address, bool set) = 0;
		virtual bool SetWatchpoint(uint32_t address, uint32_t size, WatchKind kind, bool set) = 0;
		// The client went away: drop every breakpoint and watchpoint it set.
		virtual void ClearAll() = 0;
	};

	class Server
	{
	public:
		using LogFn = std::function<void(const std::string&)>;

		Server(Target& target, LogFn log);
		~Server();

		// Listens on 127.0.0.1:port and serves one client at a time until
		// RequestStop(). Blocking: run it on a thread of its own.
		void Run(uint16_t port);
		void RequestStop() { m_stop_requested.store(true); }
		bool HasClient() const { return m_has_client.load(); }

	private:
		enum class Read
		{
			Packet,
			Interrupt, // a bare 0x03 from gdb
			Idle, // nothing complete yet; poll again
			Closed,
		};

		void Serve(intptr_t client);
		Read ReadPacket(intptr_t client, std::string& payload, int timeout_ms);
		bool SendPacket(intptr_t client, std::string_view payload);
		// Returns false when the session ends (detach, kill).
		bool Handle(intptr_t client, const std::string& packet, bool& running);
		std::string StopReply(const Stop& stop) const;
		bool Alive() const;

		Target& m_target;
		LogFn m_log;
		std::atomic<bool> m_stop_requested{false};
		std::atomic<bool> m_has_client{false};
		bool m_no_ack = false;
		Stop m_last_stop;
		std::string m_rx; // bytes received but not consumed yet
	};

	// Protocol pieces, public for the tests.
	std::string EncodeRegisters(const Registers& regs);
	bool DecodeRegisters(std::string_view hex, Registers& regs);
	// One register by gdb number, as little-endian hex; empty when unknown.
	std::string EncodeRegister(const Registers& regs, int regnum);
	bool DecodeRegister(std::string_view hex, int regnum, Registers& regs);
} // namespace GdbRsp
