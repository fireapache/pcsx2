// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// A stand-in EE for the GDB protocol core (pcsx2/DebugTools/GdbRsp.cpp), so
// the protocol can be checked against the real mips64r5900el-ps2-elf-gdb
// without building or booting the emulator. See smoke.sh.
//
// The "CPU" does not execute anything. It loads the ELF's segments into a
// 32 MB RAM (so gdb can read code and analyse prologues). A step moves pc on
// by one instruction. On resume:
//   - with breakpoints set: stops on the nearest one at or after pc;
//   - else with a watchpoint set: changes the watched word and reports it;
//   - else with --fault: reports a SIGSEGV at the current pc;
//   - else: runs until gdb interrupts it.
//
//   fake_target <elf> <port> [--fault]

#include "../../pcsx2/DebugTools/GdbRsp.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <thread>
#include <vector>

namespace
{
	constexpr uint32_t RAM_SIZE = 32 * 1024 * 1024;

	uint32_t Physical(uint32_t address) { return address & 0x1fffffff; }

	class FakeEE final : public GdbRsp::Target
	{
	public:
		FakeEE(std::vector<uint8_t> ram, uint32_t entry, bool fault)
			: m_ram(std::move(ram))
			, m_fault(fault)
		{
			m_regs.pc = entry;
			m_regs.gpr[29] = 0x01f00000; // sp
			m_regs.status = 0x70030c13;
			m_regs.fir = 0x2e30;
			float one = 1.5f;
			std::memcpy(&m_regs.fpr[0], &one, sizeof(one));
		}

		bool IsAlive() override { return true; }

		bool IsHalted() override
		{
			if (!m_running)
				return true;
			if (m_halt_requested)
				return Halt({GdbRsp::StopReason::Interrupt});
			// Let a little time pass, as a real machine would.
			if (std::chrono::steady_clock::now() - m_resumed < std::chrono::milliseconds(20))
				return false;
			if (m_stepping)
			{
				m_stepping = false;
				m_regs.pc += 4; // no branch evaluation: the fake executes nothing
				return Halt({GdbRsp::StopReason::Breakpoint});
			}
			if (!m_breakpoints.empty())
			{
				auto it = m_breakpoints.lower_bound(static_cast<uint32_t>(m_regs.pc));
				if (it == m_breakpoints.end())
					it = m_breakpoints.begin();
				m_regs.pc = *it;
				return Halt({GdbRsp::StopReason::Breakpoint});
			}
			if (!m_watchpoints.empty())
			{
				const auto& [address, kind] = *m_watchpoints.begin();
				uint32_t word;
				std::memcpy(&word, &m_ram[Physical(address)], 4);
				word++;
				std::memcpy(&m_ram[Physical(address)], &word, 4);
				return Halt({GdbRsp::StopReason::Watchpoint, kind, address});
			}
			if (m_fault)
			{
				m_regs.badvaddr = 0xdead0000;
				return Halt({GdbRsp::StopReason::Fault, GdbRsp::WatchKind::Write, 0xdead0000});
			}
			return false;
		}

		void RequestHalt() override { m_halt_requested = true; }

		void Resume() override
		{
			m_running = true;
			m_halt_requested = false;
			m_resumed = std::chrono::steady_clock::now();
		}

		void Step() override
		{
			Resume();
			m_stepping = true;
		}

		GdbRsp::Stop TakeStop() override { return m_stop; }

		void ReadRegisters(GdbRsp::Registers& regs) override { regs = m_regs; }
		void WriteRegisters(const GdbRsp::Registers& regs) override { m_regs = regs; }

		bool ReadMemory(uint32_t address, void* dest, uint32_t size) override
		{
			if (!Valid(address, size))
				return false;
			std::memcpy(dest, &m_ram[Physical(address)], size);
			return true;
		}

		bool WriteMemory(uint32_t address, const void* src, uint32_t size) override
		{
			if (!Valid(address, size))
				return false;
			std::memcpy(&m_ram[Physical(address)], src, size);
			return true;
		}

		bool SetBreakpoint(uint32_t address, bool set) override
		{
			std::printf("fake: %s breakpoint %08x\n", set ? "set" : "clear", address);
			if (set)
				m_breakpoints.insert(address);
			else
				m_breakpoints.erase(address);
			return true;
		}

		bool SetWatchpoint(uint32_t address, uint32_t size, GdbRsp::WatchKind kind, bool set) override
		{
			std::printf("fake: %s watchpoint %08x+%u\n", set ? "set" : "clear", address, size);
			if (set)
				m_watchpoints[address] = kind;
			else
				m_watchpoints.erase(address);
			return true;
		}

		void ClearAll() override
		{
			m_breakpoints.clear();
			m_watchpoints.clear();
		}

	private:
		bool Halt(const GdbRsp::Stop& stop)
		{
			m_stop = stop;
			m_running = false;
			m_halt_requested = false;
			return true;
		}

		bool Valid(uint32_t address, uint32_t size) const
		{
			// kuseg/kseg0/kseg1 views of the 32 MB; anything else is unmapped.
			const uint32_t segment = address & 0xe0000000;
			if (segment != 0 && segment != 0x80000000 && segment != 0xa0000000)
				return false;
			return Physical(address) + static_cast<uint64_t>(size) <= RAM_SIZE;
		}

		std::vector<uint8_t> m_ram;
		bool m_fault;
		GdbRsp::Registers m_regs;
		GdbRsp::Stop m_stop;
		bool m_running = false;
		bool m_halt_requested = false;
		bool m_stepping = false;
		std::chrono::steady_clock::time_point m_resumed;
		std::set<uint32_t> m_breakpoints;
		std::map<uint32_t, GdbRsp::WatchKind> m_watchpoints;
	};

	template <typename T>
	T Load(const std::vector<uint8_t>& file, size_t offset)
	{
		T value{};
		if (offset + sizeof(T) <= file.size())
			std::memcpy(&value, &file[offset], sizeof(T));
		return value;
	}

	// The PT_LOAD segments of a 32-bit little-endian ELF into RAM.
	bool LoadElf(const char* path, std::vector<uint8_t>& ram, uint32_t& entry)
	{
		std::ifstream in(path, std::ios::binary);
		const std::vector<uint8_t> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		if (file.size() < 52 || std::memcmp(file.data(), "\x7f" "ELF", 4) != 0 || file[4] != 1 || file[5] != 1)
			return false;
		entry = Load<uint32_t>(file, 24);
		const uint32_t phoff = Load<uint32_t>(file, 28);
		const uint16_t phentsize = Load<uint16_t>(file, 42);
		const uint16_t phnum = Load<uint16_t>(file, 44);
		ram.assign(RAM_SIZE, 0);
		for (uint16_t i = 0; i < phnum; i++)
		{
			const size_t ph = phoff + static_cast<size_t>(i) * phentsize;
			if (Load<uint32_t>(file, ph) != 1) // PT_LOAD
				continue;
			const uint32_t offset = Load<uint32_t>(file, ph + 4);
			const uint32_t vaddr = Physical(Load<uint32_t>(file, ph + 8));
			const uint32_t filesz = Load<uint32_t>(file, ph + 16);
			if (offset + static_cast<uint64_t>(filesz) > file.size() || vaddr + static_cast<uint64_t>(filesz) > RAM_SIZE)
				return false;
			std::memcpy(&ram[vaddr], &file[offset], filesz);
		}
		return true;
	}
} // namespace

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		std::fprintf(stderr, "usage: fake_target <elf> <port> [--fault]\n");
		return 2;
	}
	std::vector<uint8_t> ram;
	uint32_t entry = 0;
	if (!LoadElf(argv[1], ram, entry))
	{
		std::fprintf(stderr, "fake_target: cannot load %s\n", argv[1]);
		return 1;
	}
	const bool fault = argc > 3 && std::strcmp(argv[3], "--fault") == 0;
	FakeEE ee(std::move(ram), entry, fault);
	GdbRsp::Server server(ee, [](const std::string& line) {
		std::printf("gdb-server: %s\n", line.c_str());
		std::fflush(stdout);
	});
	// One session, then exit: the smoke test is a single gdb run. Nobody
	// connecting within a minute ends it too.
	std::thread watcher([&server] {
		for (int waited = 0; !server.HasClient(); waited += 10)
		{
			if (waited > 60000)
			{
				server.RequestStop();
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		while (server.HasClient())
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		server.RequestStop();
	});
	server.Run(static_cast<uint16_t>(std::atoi(argv[2])));
	watcher.join();
	return 0;
}
