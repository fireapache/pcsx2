// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "DebugTools/GdbRsp.h"

#include <gtest/gtest.h>

#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace
{
	// A machine that does nothing by itself: a test decides when it halts and why.
	class FakeTarget final : public GdbRsp::Target
	{
	public:
		FakeTarget() { ram.resize(0x1000); }

		bool IsAlive() override { return true; }
		bool IsHalted() override { return halted; }
		void RequestHalt() override { halt_requests++; }
		void Resume() override
		{
			resumes++;
			halted = false;
		}
		void Step() override
		{
			steps++;
			halted = false;
		}
		GdbRsp::Stop TakeStop() override { return stop; }

		void ReadRegisters(GdbRsp::Registers& out) override { out = regs; }
		void WriteRegisters(const GdbRsp::Registers& in) override { regs = in; }

		bool ReadMemory(u32 address, void* dest, u32 size) override
		{
			if (static_cast<u64>(address) + size > ram.size())
				return false;
			std::memcpy(dest, &ram[address], size);
			return true;
		}

		bool WriteMemory(u32 address, const void* src, u32 size) override
		{
			if (static_cast<u64>(address) + size > ram.size())
				return false;
			std::memcpy(&ram[address], src, size);
			return true;
		}

		bool SetBreakpoint(u32 address, bool set) override
		{
			if (set)
				breakpoints.insert(address);
			else
				breakpoints.erase(address);
			return true;
		}

		bool SetWatchpoint(u32 address, u32 size, GdbRsp::WatchKind kind, bool set) override
		{
			if (set)
				watchpoints[address] = {size, kind};
			else
				watchpoints.erase(address);
			return true;
		}

		void ClearAll() override
		{
			breakpoints.clear();
			watchpoints.clear();
		}

		bool halted = true;
		GdbRsp::Stop stop;
		GdbRsp::Registers regs;
		std::vector<u8> ram;
		std::set<u32> breakpoints;
		std::map<u32, std::pair<u32, GdbRsp::WatchKind>> watchpoints;
		int halt_requests = 0;
		int resumes = 0;
		int steps = 0;
	};

	std::string Frame(std::string_view payload)
	{
		u8 sum = 0;
		for (const char c : payload)
			sum = static_cast<u8>(sum + static_cast<u8>(c));
		char tail[4];
		std::snprintf(tail, sizeof(tail), "#%02x", sum);
		return "$" + std::string(payload) + tail;
	}

	// One session, already past Begin(), recording everything it sends.
	struct Harness
	{
		Harness()
			: session(target, [this](std::string_view bytes) { sent += bytes; })
		{
			session.Begin();
		}

		// Sends one packet; returns the payload of the reply ("" when the packet
		// got only an acknowledgement).
		std::string Ask(std::string_view payload)
		{
			sent.clear();
			alive = session.Receive(Frame(payload));
			return LastPayload();
		}

		std::string LastPayload() const
		{
			const size_t start = sent.rfind('$');
			const size_t end = sent.rfind('#');
			if (start == std::string::npos || end == std::string::npos || end < start)
				return std::string();
			return sent.substr(start + 1, end - start - 1);
		}

		FakeTarget target;
		GdbRsp::Session session;
		std::string sent;
		bool alive = true;
	};

	std::string Hex64(u64 value)
	{
		std::string out;
		for (int i = 0; i < 8; i++)
		{
			char byte[3];
			std::snprintf(byte, sizeof(byte), "%02x", static_cast<unsigned>((value >> (i * 8)) & 0xff));
			out += byte;
		}
		return out;
	}
} // namespace

TEST(GdbRsp, AcknowledgesValidPacketsAndRejectsDamagedOnes)
{
	Harness h;
	h.Ask("?");
	EXPECT_EQ(h.sent.substr(0, 1), "+");

	h.sent.clear();
	h.session.Receive("$?#00");
	EXPECT_EQ(h.sent, "-");
}

TEST(GdbRsp, NoAckModeStopsAcknowledgements)
{
	Harness h;
	EXPECT_EQ(h.Ask("QStartNoAckMode"), "OK");
	h.Ask("?");
	EXPECT_EQ(h.sent.find('+'), std::string::npos);
}

TEST(GdbRsp, AttachReportsAPlainStop)
{
	Harness h;
	EXPECT_EQ(h.Ask("?"), "T05");
	EXPECT_EQ(h.Ask("qAttached"), "1");
}

TEST(GdbRsp, RegistersUseTheEightByteLayout)
{
	Harness h;
	h.target.regs.gpr[29] = 0x01f00000;
	h.target.regs.pc = 0xffffffff80001000ull;
	h.target.regs.fpr[0] = 0x3fc00000; // 1.5f
	h.target.regs.status = 0x70030c13;

	const std::string g = h.Ask("g");
	ASSERT_EQ(g.size(), 72u * 16u);
	EXPECT_EQ(g.substr(29 * 16, 16), Hex64(0x01f00000));
	EXPECT_EQ(g.substr(32 * 16, 16), Hex64(0x70030c13)); // status, zero-extended
	EXPECT_EQ(g.substr(37 * 16, 16), Hex64(0xffffffff80001000ull)); // pc
	EXPECT_EQ(g.substr(38 * 16, 16), Hex64(0x3fc00000)); // f0, in the low word
	EXPECT_EQ(h.Ask("p25"), Hex64(0xffffffff80001000ull)); // register 0x25 = pc
}

TEST(GdbRsp, RegisterWritesRoundTrip)
{
	Harness h;
	GdbRsp::Registers regs;
	regs.gpr[4] = 0x1234;
	regs.fpr[2] = 0x40000000;
	EXPECT_EQ(h.Ask("G" + GdbRsp::EncodeRegisters(regs)), "OK");
	EXPECT_EQ(h.target.regs.gpr[4], 0x1234u);
	EXPECT_EQ(h.target.regs.fpr[2], 0x40000000u);

	EXPECT_EQ(h.Ask("P5=" + Hex64(0xbeef)), "OK");
	EXPECT_EQ(h.target.regs.gpr[5], 0xbeefu);
	EXPECT_EQ(h.Ask("P99=" + Hex64(1)), "E01");
}

TEST(GdbRsp, ReadsAndWritesMemory)
{
	Harness h;
	h.target.ram[0x10] = 0xab;
	h.target.ram[0x11] = 0xcd;
	EXPECT_EQ(h.Ask("m10,2"), "abcd");
	EXPECT_EQ(h.Ask("mffffffff00000010,2"), "abcd"); // sign-extended, as gdb sends kseg addresses
	EXPECT_EQ(h.Ask("m2000,4"), "E01");

	EXPECT_EQ(h.Ask("M20,2:1122"), "OK");
	EXPECT_EQ(h.target.ram[0x20], 0x11);
	EXPECT_EQ(h.target.ram[0x21], 0x22);

	// X carries binary data, '}' escaping the bytes the framing uses.
	EXPECT_EQ(h.Ask("X30,0:"), "OK");
	EXPECT_EQ(h.Ask(std::string("X30,2:") + "}" + static_cast<char>('#' ^ 0x20) + "A"), "OK");
	EXPECT_EQ(h.target.ram[0x30], '#');
	EXPECT_EQ(h.target.ram[0x31], 'A');
}

TEST(GdbRsp, BreakpointsAndWatchpointsReachTheTarget)
{
	Harness h;
	EXPECT_EQ(h.Ask("Z0,442028,4"), "OK");
	EXPECT_EQ(h.target.breakpoints.count(0x442028), 1u);
	EXPECT_EQ(h.Ask("z0,442028,4"), "OK");
	EXPECT_TRUE(h.target.breakpoints.empty());

	EXPECT_EQ(h.Ask("Z2,500000,4"), "OK");
	EXPECT_EQ(h.target.watchpoints.at(0x500000).second, GdbRsp::WatchKind::Write);
	EXPECT_EQ(h.Ask("Z4,500010,8"), "OK");
	EXPECT_EQ(h.target.watchpoints.at(0x500010).second, GdbRsp::WatchKind::Access);
	EXPECT_EQ(h.Ask("Z9,0,4"), ""); // unsupported type
}

TEST(GdbRsp, ContinueRepliesWithTheNextStop)
{
	Harness h;
	h.Ask("c");
	EXPECT_EQ(h.target.resumes, 1);
	EXPECT_TRUE(h.session.IsRunning());
	EXPECT_EQ(h.LastPayload(), ""); // no reply until the machine stops

	h.sent.clear();
	h.session.Poll();
	EXPECT_EQ(h.sent, ""); // still running

	h.target.stop = {GdbRsp::StopReason::Fault, GdbRsp::WatchKind::Write, 0xdead0000};
	h.target.halted = true;
	h.session.Poll();
	EXPECT_EQ(h.LastPayload(), "T0b");
	EXPECT_FALSE(h.session.IsRunning());
}

TEST(GdbRsp, WatchpointStopsNameTheAddress)
{
	Harness h;
	h.Ask("c");
	h.target.stop = {GdbRsp::StopReason::Watchpoint, GdbRsp::WatchKind::Read, 0x500000};
	h.target.halted = true;
	h.session.Poll();
	EXPECT_EQ(h.LastPayload(), "T05rwatch:500000;");
}

TEST(GdbRsp, ContinueWithASignalAndAnAddressMovesPc)
{
	Harness h;
	h.Ask("C0b;100e78");
	EXPECT_EQ(h.target.regs.pc, 0x100e78u);
	EXPECT_EQ(h.target.resumes, 1);
}

TEST(GdbRsp, StepGoesToTheTarget)
{
	Harness h;
	h.Ask("s");
	EXPECT_EQ(h.target.steps, 1);
	h.target.stop = {GdbRsp::StopReason::Breakpoint};
	h.target.halted = true;
	h.session.Poll();
	EXPECT_EQ(h.LastPayload(), "T05");
}

TEST(GdbRsp, InterruptOnlyWhileRunning)
{
	Harness h;
	h.session.Receive("\x03");
	EXPECT_EQ(h.target.halt_requests, 0);
	h.Ask("c");
	h.session.Receive("\x03");
	EXPECT_EQ(h.target.halt_requests, 1);
}

TEST(GdbRsp, DetachAndKillEndTheSession)
{
	{
		Harness h;
		EXPECT_EQ(h.Ask("D"), "OK");
		EXPECT_FALSE(h.alive);
	}
	{
		Harness h;
		EXPECT_EQ(h.Ask("vKill;1"), "OK");
		EXPECT_FALSE(h.alive);
	}
	{
		Harness h;
		h.Ask("k");
		EXPECT_FALSE(h.alive);
	}
}

TEST(GdbRsp, UnknownPacketsGetAnEmptyReply)
{
	Harness h;
	EXPECT_EQ(h.Ask("vCont?"), "");
	EXPECT_TRUE(h.alive);
	EXPECT_EQ(h.sent, "+$#00");
}

TEST(GdbRsp, PacketsSplitAcrossReadsAreReassembled)
{
	Harness h;
	const std::string packet = Frame("qAttached");
	h.sent.clear();
	h.session.Receive(packet.substr(0, 4));
	EXPECT_EQ(h.sent, "");
	h.session.Receive(packet.substr(4));
	EXPECT_EQ(h.LastPayload(), "1");
}
