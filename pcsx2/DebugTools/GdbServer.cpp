// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "DebugTools/GdbServer.h"
#include "DebugTools/Breakpoints.h"
#include "DebugTools/DebugInterface.h"
#include "DebugTools/GdbRsp.h"
#include "DebugTools/MIPSAnalyst.h"
#include "Host.h"
#include "R5900.h"
#include "VMManager.h"

#include "common/Console.h"
#include "common/Threading.h"

#include "fmt/format.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{
	// Set by OnMemoryFault, consumed by the next stop report; both on the CPU thread.
	bool s_fault_pending = false;
	u32 s_fault_address = 0;
	std::string s_fault_message;

	// Shutdown joins the server thread FROM the CPU thread, so the server must
	// never block on the CPU thread outright: every call below is posted, and
	// its wait gives up once the server is stopping.
	std::atomic<bool> s_stopping{false};

	template <typename T>
	std::optional<T> CallOnCPU(std::function<T()> fn)
	{
		struct Call
		{
			std::atomic<bool> done{false};
			T value{};
		};
		// Shared, not on this stack: an abandoned call still runs later.
		auto call = std::make_shared<Call>();
		Host::RunOnCPUThread([fn = std::move(fn), call] {
			call->value = fn();
			call->done.store(true, std::memory_order_release);
		});
		while (!call->done.load(std::memory_order_acquire))
		{
			if (s_stopping.load())
				return std::nullopt;
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		return call->value;
	}

	bool RunOnCPU(std::function<bool()> fn)
	{
		return CallOnCPU<bool>(std::move(fn)).value_or(false);
	}

	MemCheckCondition MemCheckFor(GdbRsp::WatchKind kind)
	{
		switch (kind)
		{
			case GdbRsp::WatchKind::Read:
				return MEMCHECK_READ;
			case GdbRsp::WatchKind::Access:
				return MEMCHECK_READWRITE;
			case GdbRsp::WatchKind::Write:
			default:
				return MEMCHECK_WRITE;
		}
	}

	// The EE behind the protocol. Called from the server thread only; the
	// bookkeeping (what this client set) lives here, the emulator state is
	// touched on the CPU thread as the Qt debugger does.
	class EETarget final : public GdbRsp::Target
	{
	public:
		bool IsAlive() override { return VMManager::HasValidVM(); }

		bool IsHalted() override { return VMManager::GetState() == VMState::Paused; }

		void RequestHalt() override
		{
			Host::RunOnCPUThread([] { VMManager::SetPaused(true); });
		}

		void Resume() override { Run(false); }

		void Step() override { Run(true); }

		GdbRsp::Stop TakeStop() override
		{
			struct Seen
			{
				bool fault = false;
				u32 fault_address = 0;
				std::string fault_message;
				bool triggered = false;
				std::vector<MemCheck> memchecks;
			};
			// On the CPU thread: getting there also means the EE has left the
			// block it stopped in, so the registers read next are settled.
			const auto seen = CallOnCPU<Seen>([] {
				Seen s;
				s.fault = std::exchange(s_fault_pending, false);
				s.fault_address = s_fault_address;
				s.fault_message = std::move(s_fault_message);
				s.triggered = CBreakPoints::GetBreakpointTriggered();
				if (s.triggered)
				{
					s.memchecks = CBreakPoints::GetMemChecks(BREAKPOINT_EE);
					// The Qt debugger clears these in its own pause handler; with
					// only gdb watching nobody would.
					CBreakPoints::ClearTemporaryBreakPoints();
					CBreakPoints::SetBreakpointTriggered(false, BREAKPOINT_IOP_AND_EE);
				}
				return s;
			});

			GdbRsp::Stop stop;
			if (!seen)
				return stop;
			if (seen->fault)
			{
				stop.reason = GdbRsp::StopReason::Fault;
				stop.data_address = seen->fault_address;
				stop.message = seen->fault_message;
			}
			else if (seen->triggered)
			{
				stop.reason = GdbRsp::StopReason::Breakpoint;
				for (const auto& [range, watch] : m_watches)
				{
					if (HitsOf(seen->memchecks, range) == watch.hits_at_resume)
						continue;
					stop.reason = GdbRsp::StopReason::Watchpoint;
					stop.watch_kind = watch.kind;
					stop.data_address = LastAddressOf(seen->memchecks, range);
					break;
				}
			}
			// Otherwise: paused by gdb's interrupt or by hand -> Interrupt.
			return stop;
		}

		void ReadRegisters(GdbRsp::Registers& regs) override
		{
			// Read from this thread while paused, as the Qt debugger's register
			// view reads from the UI thread.
			for (int i = 0; i < 32; i++)
				regs.gpr[i] = r5900Debug.getRegister(EECAT_GPR, i)._u64[0];
			regs.hi = r5900Debug.getRegister(EECAT_GPR, 33)._u64[0];
			regs.lo = r5900Debug.getRegister(EECAT_GPR, 34)._u64[0];
			// n32: a 32-bit address in a 64-bit register is sign-extended.
			regs.pc = static_cast<u64>(static_cast<s64>(static_cast<s32>(r5900Debug.getPC())));
			regs.status = r5900Debug.getRegister(EECAT_CP0, 12)._u32[0];
			regs.badvaddr = r5900Debug.getRegister(EECAT_CP0, 8)._u32[0];
			regs.cause = r5900Debug.getRegister(EECAT_CP0, 13)._u32[0];
			for (int i = 0; i < 32; i++)
				regs.fpr[i] = r5900Debug.getRegister(EECAT_FPR, i)._u32[0];
			regs.fcsr = r5900Debug.getRegister(EECAT_FCR, 31)._u32[0];
			regs.fir = r5900Debug.getRegister(EECAT_FCR, 0)._u32[0];
		}

		void WriteRegisters(const GdbRsp::Registers& regs) override
		{
			RunOnCPU([regs] {
				// gdb sees the low 64 bits of each GPR; keep the upper half (MMI data).
				auto set_low = [](int cat, int num, u64 value) {
					u128 reg = r5900Debug.getRegister(cat, num);
					reg._u64[0] = value;
					r5900Debug.setRegister(cat, num, reg);
				};
				for (int i = 1; i < 32; i++) // r0 is hard-wired
					set_low(EECAT_GPR, i, regs.gpr[i]);
				set_low(EECAT_GPR, 33, regs.hi);
				set_low(EECAT_GPR, 34, regs.lo);
				r5900Debug.setPc(static_cast<u32>(regs.pc));
				r5900Debug.setRegister(EECAT_CP0, 12, u128::From32(regs.status));
				r5900Debug.setRegister(EECAT_CP0, 8, u128::From32(regs.badvaddr));
				r5900Debug.setRegister(EECAT_CP0, 13, u128::From32(regs.cause));
				for (int i = 0; i < 32; i++)
					r5900Debug.setRegister(EECAT_FPR, i, u128::From32(regs.fpr[i]));
				r5900Debug.setRegister(EECAT_FCR, 31, u128::From32(regs.fcsr));
				// fir is read-only.
				return true;
			});
		}

		bool ReadMemory(u32 address, void* dest, u32 size) override
		{
			return r5900Debug.ReadBytes(address, dest, size);
		}

		bool WriteMemory(u32 address, const void* src, u32 size) override
		{
			std::vector<u8> bytes(static_cast<const u8*>(src), static_cast<const u8*>(src) + size);
			return RunOnCPU([address, bytes = std::move(bytes)] {
				if (!r5900Debug.WriteBytes(address, bytes.data(), static_cast<u32>(bytes.size())))
					return false;
				// The recompiler may hold a translation of what was just written.
				Cpu->Clear(address & ~3u, (static_cast<u32>(bytes.size()) + (address & 3u) + 3u) / 4u);
				return true;
			});
		}

		bool SetBreakpoint(u32 address, bool set) override
		{
			const bool ok = RunOnCPU([address, set] {
				if (set)
					CBreakPoints::AddBreakPoint(BREAKPOINT_EE, address);
				else
					CBreakPoints::RemoveBreakPoint(BREAKPOINT_EE, address);
				return true;
			});
			if (ok)
			{
				if (set)
					m_breakpoints.insert(address);
				else
					m_breakpoints.erase(address);
			}
			return ok;
		}

		bool SetWatchpoint(u32 address, u32 size, GdbRsp::WatchKind kind, bool set) override
		{
			const u32 end = address + std::max<u32>(size, 1);
			const MemCheckCondition cond = MemCheckFor(kind);
			const bool ok = RunOnCPU([address, end, cond, set] {
				if (set)
					CBreakPoints::AddMemCheck(BREAKPOINT_EE, address, end, cond, MEMCHECK_BREAK);
				else
					CBreakPoints::RemoveMemCheck(BREAKPOINT_EE, address, end);
				return true;
			});
			if (ok)
			{
				if (set)
					m_watches[{address, end}] = Watch{kind, 0};
				else
					m_watches.erase({address, end});
			}
			return ok;
		}

		void ClearAll() override
		{
			std::vector<u32> breakpoints(m_breakpoints.begin(), m_breakpoints.end());
			std::vector<std::pair<u32, u32>> watches;
			for (const auto& [range, watch] : m_watches)
				watches.push_back(range);
			m_breakpoints.clear();
			m_watches.clear();
			RunOnCPU([breakpoints = std::move(breakpoints), watches = std::move(watches)] {
				for (u32 address : breakpoints)
					CBreakPoints::RemoveBreakPoint(BREAKPOINT_EE, address);
				for (const auto& [start, end] : watches)
					CBreakPoints::RemoveMemCheck(BREAKPOINT_EE, start, end);
				return true;
			});
		}

	private:
		struct Watch
		{
			GdbRsp::WatchKind kind;
			u32 hits_at_resume;
		};

		void Run(bool step)
		{
			// Remember each watchpoint's hit count, so the next stop can tell
			// which one fired.
			const auto hits = CallOnCPU<std::vector<MemCheck>>([] { return CBreakPoints::GetMemChecks(BREAKPOINT_EE); });
			if (hits)
			{
				for (auto& [range, watch] : m_watches)
					watch.hits_at_resume = HitsOf(*hits, range);
			}
			RunOnCPU([step] {
				const u32 pc = r5900Debug.getPC();
				// A breakpoint on the resume pc would stop again at once.
				CBreakPoints::SetSkipFirst(BREAKPOINT_EE, pc);
				if (step)
					CBreakPoints::AddBreakPoint(BREAKPOINT_EE, NextPC(pc), true, true, true);
				VMManager::SetPaused(false);
				return true;
			});
		}

		// Where one step from pc lands, worked out as the Qt debugger's Step
		// Into does: a branch runs with its delay slot, a syscall is taken.
		// Needs proper testing: an interrupt or exception taken during the step
		// runs on until the handler returns to the stepping breakpoint.
		static u32 NextPC(u32 pc)
		{
			const MIPSAnalyst::MipsOpcodeInfo info = MIPSAnalyst::GetOpcodeInfo(&r5900Debug, pc);
			if (info.isSyscall)
				return info.branchTarget;
			if (info.isBranch)
				return (!info.isConditional || info.conditionMet) ? info.branchTarget : pc + 8;
			return pc + 4;
		}

		static u32 HitsOf(const std::vector<MemCheck>& checks, const std::pair<u32, u32>& range)
		{
			for (const MemCheck& mc : checks)
			{
				if (mc.start == range.first && mc.end == range.second)
					return mc.totalHits;
			}
			return 0;
		}

		static u32 LastAddressOf(const std::vector<MemCheck>& checks, const std::pair<u32, u32>& range)
		{
			for (const MemCheck& mc : checks)
			{
				if (mc.start == range.first && mc.end == range.second)
					return mc.lastAddr;
			}
			return range.first;
		}

		std::set<u32> m_breakpoints;
		std::map<std::pair<u32, u32>, Watch> m_watches;
	};

	// Owned by the CPU thread (Reload / Shutdown / OnMemoryFault all run there).
	std::unique_ptr<EETarget> s_target;
	std::unique_ptr<GdbRsp::Server> s_server;
	std::thread s_thread;
	u16 s_port = 0;

	u16 ConfiguredPort()
	{
		int port = 0;
		if (const char* env = std::getenv("PCSX2_GDB_PORT"); env && *env)
			port = std::atoi(env);
		else
			port = Host::GetBaseIntSettingValue("EmuCore", "GdbServerPort", 0);
		return static_cast<u16>(std::clamp(port, 0, 65535));
	}

	bool ConfiguredWait()
	{
		if (const char* env = std::getenv("PCSX2_GDB_WAIT"); env && *env)
			return std::strcmp(env, "0") != 0;
		return Host::GetBaseBoolSettingValue("EmuCore", "GdbServerWait", false);
	}

	void Stop()
	{
		if (!s_server)
			return;
		s_stopping.store(true);
		s_server->RequestStop();
		if (s_thread.joinable())
			s_thread.join();
		s_server.reset();
		s_target.reset();
		s_port = 0;
		s_stopping.store(false);
	}
} // namespace

void GdbServer::Reload()
{
	const u16 port = ConfiguredPort();
	if (port == s_port && (port == 0) == !s_server)
		return;

	Stop();
	if (port == 0)
		return;

	s_target = std::make_unique<EETarget>();
	s_server = std::make_unique<GdbRsp::Server>(*s_target, [](const std::string& line) {
		Console.WriteLnFmt("GDB server: {}", line);
	});
	s_port = port;
	s_thread = std::thread([server = s_server.get(), port] {
		Threading::SetNameOfCurrentThread("GDB Server");
		server->Run(port);
	});

	// A debugger needs a few seconds to load symbols and attach, by which time a
	// game's startup has run. Waiting holds the game at its ELF's entry point -
	// the debugger's Boot and Debug - until a client attaches and continues.
	if (ConfiguredWait())
		DebugInterface::setPauseOnEntry(true);
}

void GdbServer::Shutdown()
{
	Stop();
}

bool GdbServer::OnMemoryFault(u32 address, bool store, bool exact)
{
	if (!s_server || !s_server->HasClient())
		return false;
	s_fault_pending = true;
	s_fault_address = address;
	s_fault_message = fmt::format("PCSX2: {} at unmapped address 0x{:08x}.\n", store ? "store" : "load", address);
	if (!exact)
	{
		// The recompiler only checks for the pause at the end of a block, so the
		// stop can be a few instructions - even a return or two - later.
		s_fault_message += "PCSX2: the EE recompiler stops after the faulting instruction; switch the EE to the "
						   "interpreter for an exact stop.\n";
	}
	Console.Error(s_fault_message);
	return true;
}
