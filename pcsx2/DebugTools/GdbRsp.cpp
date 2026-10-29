// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "GdbRsp.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
static void CloseSocket(socket_t s)
{
	closesocket(s);
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t INVALID_SOCKET_VALUE = -1;
static void CloseSocket(socket_t s)
{
	close(s);
}
#endif

namespace GdbRsp
{
	namespace
	{
		// Registers travel in gdb's mips numbering: r0-r31, then these.
		constexpr int REG_STATUS = 32;
		constexpr int REG_LO = 33;
		constexpr int REG_HI = 34;
		constexpr int REG_BADVADDR = 35;
		constexpr int REG_CAUSE = 36;
		constexpr int REG_PC = 37;
		constexpr int REG_F0 = 38;
		constexpr int REG_FCSR = 70;
		constexpr int REG_FIR = 71;
		constexpr int REG_COUNT = 72;

		// No target description is offered: the PS2 toolchain's gdb is built
		// without XML support and would ignore one. It uses its built-in
		// mips:5900 n32 layout instead, where EVERY register is 8 bytes - the
		// FPRs and the 32-bit control registers too - so each travels as 8
		// bytes, 32-bit values zero-extended. A g reply may stop at any register
		// boundary; gdb's extra embedded-target registers are left out.
		constexpr size_t WIRE_BYTES = 8;

		// The largest memory read answered at once (PacketSize is in hex chars).
		constexpr u32 MAX_MEMORY_CHUNK = 0x1000;

		bool RegisterField(const Registers& regs, int regnum, const void*& field, size_t& size)
		{
			if (regnum >= 0 && regnum < 32)
			{
				field = &regs.gpr[regnum];
				size = sizeof(u64);
				return true;
			}
			if (regnum >= REG_F0 && regnum < REG_F0 + 32)
			{
				field = &regs.fpr[regnum - REG_F0];
				size = sizeof(u32);
				return true;
			}
			switch (regnum)
			{
				case REG_STATUS:
					field = &regs.status;
					break;
				case REG_LO:
					field = &regs.lo;
					break;
				case REG_HI:
					field = &regs.hi;
					break;
				case REG_BADVADDR:
					field = &regs.badvaddr;
					break;
				case REG_CAUSE:
					field = &regs.cause;
					break;
				case REG_PC:
					field = &regs.pc;
					break;
				case REG_FCSR:
					field = &regs.fcsr;
					break;
				case REG_FIR:
					field = &regs.fir;
					break;
				default:
					return false;
			}
			size = (regnum == REG_LO || regnum == REG_HI || regnum == REG_PC) ? sizeof(u64) : sizeof(u32);
			return true;
		}

		int HexValue(char c)
		{
			if (c >= '0' && c <= '9')
				return c - '0';
			if (c >= 'a' && c <= 'f')
				return c - 'a' + 10;
			if (c >= 'A' && c <= 'F')
				return c - 'A' + 10;
			return -1;
		}

		void AppendHex(std::string& out, const void* data, size_t size)
		{
			static constexpr char digits[] = "0123456789abcdef";
			const u8* bytes = static_cast<const u8*>(data);
			for (size_t i = 0; i < size; i++)
			{
				out += digits[bytes[i] >> 4];
				out += digits[bytes[i] & 0xf];
			}
		}

		bool DecodeHex(std::string_view hex, void* out, size_t size)
		{
			if (hex.size() != size * 2)
				return false;
			u8* bytes = static_cast<u8*>(out);
			for (size_t i = 0; i < size; i++)
			{
				const int hi = HexValue(hex[i * 2]);
				const int lo = HexValue(hex[i * 2 + 1]);
				if (hi < 0 || lo < 0)
					return false;
				bytes[i] = static_cast<u8>((hi << 4) | lo);
			}
			return true;
		}

		// A whole hex number. Empty or junk is an error.
		bool ParseNumber(std::string_view s, u64& value)
		{
			if (s.empty() || s.size() > 16)
				return false;
			value = 0;
			for (const char c : s)
			{
				const int digit = HexValue(c);
				if (digit < 0)
					return false;
				value = (value << 4) | static_cast<u64>(digit);
			}
			return true;
		}

		// "addr,len". gdb sign-extends kseg addresses for an n32 program
		// (0xffffffff80001000); the EE has 32 address bits, the low half.
		bool ParseAddressLength(std::string_view s, u32& address, u32& length)
		{
			const size_t comma = s.find(',');
			u64 a, l;
			if (comma == std::string_view::npos || !ParseNumber(s.substr(0, comma), a) ||
				!ParseNumber(s.substr(comma + 1), l) || l > 0xffffffffu)
				return false;
			address = static_cast<u32>(a);
			length = static_cast<u32>(l);
			return true;
		}

		std::string UnescapeBinary(std::string_view data)
		{
			std::string out;
			out.reserve(data.size());
			for (size_t i = 0; i < data.size(); i++)
			{
				if (data[i] == '}' && i + 1 < data.size())
					out += static_cast<char>(data[++i] ^ 0x20);
				else
					out += data[i];
			}
			return out;
		}

		u8 Checksum(std::string_view payload)
		{
			u8 sum = 0;
			for (const char c : payload)
				sum = static_cast<u8>(sum + static_cast<u8>(c));
			return sum;
		}

		std::string EncodeRegister(const Registers& regs, int regnum)
		{
			const void* field;
			size_t size;
			std::string out;
			if (!RegisterField(regs, regnum, field, size))
				return out;
			u8 wire[WIRE_BYTES] = {};
			std::memcpy(wire, field, size);
			AppendHex(out, wire, sizeof(wire));
			return out;
		}

		bool DecodeRegister(std::string_view hex, int regnum, Registers& regs)
		{
			const void* field;
			size_t size;
			u8 wire[WIRE_BYTES];
			if (!RegisterField(regs, regnum, field, size) || !DecodeHex(hex, wire, sizeof(wire)))
				return false;
			std::memcpy(const_cast<void*>(field), wire, size);
			return true;
		}
	} // namespace

	std::string EncodeRegisters(const Registers& regs)
	{
		std::string out;
		for (int i = 0; i < REG_COUNT; i++)
			out += EncodeRegister(regs, i);
		return out;
	}

	bool DecodeRegisters(std::string_view hex, Registers& regs)
	{
		// gdb may send its whole (longer) layout back: what follows fir is ignored.
		constexpr size_t chars = WIRE_BYTES * 2;
		if (hex.size() < REG_COUNT * chars)
			return false;
		Registers decoded = regs;
		for (int i = 0; i < REG_COUNT; i++)
		{
			if (!DecodeRegister(hex.substr(static_cast<size_t>(i) * chars, chars), i, decoded))
				return false;
		}
		regs = decoded;
		return true;
	}

	Session::Session(Target& target, SendFunction send)
		: m_target(target)
		, m_send(std::move(send))
	{
	}

	void Session::Begin()
	{
		m_rx.clear();
		m_running = false;
		m_no_ack = false;
		m_last_stop = m_target.TakeStop();
		// Attaching reads as a plain stop, not as "received SIGINT".
		if (m_last_stop.reason == StopReason::Interrupt)
			m_last_stop.reason = StopReason::Breakpoint;
	}

	bool Session::Receive(std::string_view bytes)
	{
		m_rx.append(bytes);
		while (!m_rx.empty())
		{
			if (m_rx[0] != '$')
			{
				const char c = m_rx[0];
				m_rx.erase(0, 1);
				// A bare 0x03 is gdb's interrupt; '+' and '-' are acknowledgements.
				if (c == '\x03' && m_running)
					m_target.RequestHalt();
				continue;
			}

			// Binary payloads escape '#', so the first one ends the packet.
			const size_t hash = m_rx.find('#');
			if (hash == std::string::npos || m_rx.size() < hash + 3)
				break; // incomplete

			const std::string packet = m_rx.substr(1, hash - 1);
			const int hi = HexValue(m_rx[hash + 1]);
			const int lo = HexValue(m_rx[hash + 2]);
			m_rx.erase(0, hash + 3);
			const bool valid = hi >= 0 && lo >= 0 && ((hi << 4) | lo) == Checksum(packet);
			if (!m_no_ack)
				m_send(valid ? "+" : "-");
			// gdb resends a damaged packet. Anything sent while the machine runs
			// would be non-stop mode, which is not offered.
			if (!valid || m_running)
				continue;
			if (!HandlePacket(packet))
				return false;
		}
		return true;
	}

	void Session::Poll()
	{
		if (!m_running || !m_target.IsHalted())
			return;
		m_last_stop = m_target.TakeStop();
		m_running = false;
		// Console output is only accepted while gdb waits for the stop reply.
		if (!m_last_stop.message.empty())
		{
			std::string packet = "O";
			AppendHex(packet, m_last_stop.message.data(), m_last_stop.message.size());
			SendPacket(packet);
		}
		SendPacket(StopReply());
	}

	void Session::Exited()
	{
		SendPacket("W00");
	}

	void Session::SendPacket(std::string_view payload)
	{
		static constexpr char digits[] = "0123456789abcdef";
		const u8 sum = Checksum(payload);
		std::string framed;
		framed.reserve(payload.size() + 4);
		framed += '$';
		framed += payload;
		framed += '#';
		framed += digits[sum >> 4];
		framed += digits[sum & 0xf];
		m_send(framed);
	}

	std::string Session::StopReply() const
	{
		switch (m_last_stop.reason)
		{
			case StopReason::Interrupt:
				return "T02"; // SIGINT
			case StopReason::Fault:
				return "T0b"; // SIGSEGV
			case StopReason::Watchpoint:
			{
				const char* kind = m_last_stop.watch_kind == WatchKind::Read   ? "rwatch" :
				                   m_last_stop.watch_kind == WatchKind::Access ? "awatch" :
				                                                                 "watch";
				char reply[48];
				std::snprintf(reply, sizeof(reply), "T05%s:%x;", kind, m_last_stop.data_address);
				return reply;
			}
			case StopReason::Breakpoint:
			default:
				return "T05"; // SIGTRAP
		}
	}

	bool Session::HandlePacket(std::string_view packet)
	{
		if (packet.empty())
		{
			SendPacket("");
			return true;
		}

		if (packet == "?")
		{
			SendPacket(StopReply());
			return true;
		}

		if (packet.starts_with("qSupported"))
		{
			SendPacket("PacketSize=4000;QStartNoAckMode+");
			return true;
		}

		if (packet == "QStartNoAckMode")
		{
			// This OK is still acknowledged; nothing after it is.
			SendPacket("OK");
			m_no_ack = true;
			return true;
		}

		if (packet == "qAttached")
		{
			SendPacket("1"); // an existing process: gdb detaches rather than kills
			return true;
		}

		if (packet.starts_with("qSymbol"))
		{
			SendPacket("OK");
			return true;
		}

		switch (packet[0])
		{
			case 'H': // one thread of execution
				SendPacket("OK");
				return true;

			case 'g':
			{
				Registers regs;
				m_target.ReadRegisters(regs);
				SendPacket(EncodeRegisters(regs));
				return true;
			}

			case 'G':
			{
				Registers regs;
				m_target.ReadRegisters(regs);
				if (!DecodeRegisters(packet.substr(1), regs))
				{
					SendPacket("E01");
					return true;
				}
				m_target.WriteRegisters(regs);
				SendPacket("OK");
				return true;
			}

			case 'p':
			{
				u64 regnum;
				Registers regs;
				m_target.ReadRegisters(regs);
				const std::string value = ParseNumber(packet.substr(1), regnum) ?
				                              EncodeRegister(regs, static_cast<int>(regnum)) :
				                              std::string();
				SendPacket(value.empty() ? "E01" : value);
				return true;
			}

			case 'P':
			{
				const size_t equals = packet.find('=');
				u64 regnum;
				Registers regs;
				m_target.ReadRegisters(regs);
				if (equals == std::string_view::npos || !ParseNumber(packet.substr(1, equals - 1), regnum) ||
					!DecodeRegister(packet.substr(equals + 1), static_cast<int>(regnum), regs))
				{
					SendPacket("E01");
					return true;
				}
				m_target.WriteRegisters(regs);
				SendPacket("OK");
				return true;
			}

			case 'm':
			{
				u32 address, length;
				if (!ParseAddressLength(packet.substr(1), address, length))
				{
					SendPacket("E01");
					return true;
				}
				length = std::min(length, MAX_MEMORY_CHUNK);
				std::string bytes(length, '\0');
				if (!m_target.ReadMemory(address, bytes.data(), length))
				{
					SendPacket("E01");
					return true;
				}
				std::string hex;
				AppendHex(hex, bytes.data(), bytes.size());
				SendPacket(hex);
				return true;
			}

			case 'M':
			case 'X':
			{
				const size_t colon = packet.find(':');
				u32 address, length;
				std::string bytes;
				bool ok = colon != std::string_view::npos &&
				          ParseAddressLength(packet.substr(1, colon - 1), address, length);
				if (ok && packet[0] == 'X')
				{
					bytes = UnescapeBinary(packet.substr(colon + 1));
				}
				else if (ok)
				{
					bytes.resize(length);
					ok = DecodeHex(packet.substr(colon + 1), bytes.data(), length);
				}
				ok = ok && bytes.size() == length;
				// A zero-length X is gdb probing for binary writes.
				if (ok && length > 0)
					ok = m_target.WriteMemory(address, bytes.data(), length);
				SendPacket(ok ? "OK" : "E01");
				return true;
			}

			case 'c':
			case 'C':
			case 's':
			case 'S':
			{
				// "c[addr]", "s[addr]", "Csig[;addr]", "Ssig[;addr]". The signal
				// is dropped - there is no process to deliver it to; gdb passes
				// SIGSEGV on by default, so continuing after a fault sends C0b.
				std::string_view address_text;
				if (packet[0] == 'c' || packet[0] == 's')
					address_text = packet.substr(1);
				else if (const size_t semi = packet.find(';'); semi != std::string_view::npos)
					address_text = packet.substr(semi + 1);
				if (!address_text.empty())
				{
					u64 address;
					if (!ParseNumber(address_text, address))
					{
						SendPacket("E01");
						return true;
					}
					Registers regs;
					m_target.ReadRegisters(regs);
					regs.pc = address;
					m_target.WriteRegisters(regs);
				}
				if (packet[0] == 's' || packet[0] == 'S')
					m_target.Step();
				else
					m_target.Resume();
				m_running = true; // the reply is the next stop
				return true;
			}

			case 'Z':
			case 'z':
			{
				const bool set = packet[0] == 'Z';
				u32 address, length;
				if (packet.size() < 3 || packet[2] != ',' || !ParseAddressLength(packet.substr(3), address, length))
				{
					SendPacket("E01");
					return true;
				}
				bool ok;
				switch (packet[1])
				{
					case '0': // software breakpoint
					case '1': // hardware breakpoint: the emulator's are both
						ok = m_target.SetBreakpoint(address, set);
						break;
					case '2':
						ok = m_target.SetWatchpoint(address, length, WatchKind::Write, set);
						break;
					case '3':
						ok = m_target.SetWatchpoint(address, length, WatchKind::Read, set);
						break;
					case '4':
						ok = m_target.SetWatchpoint(address, length, WatchKind::Access, set);
						break;
					default:
						SendPacket("");
						return true;
				}
				SendPacket(ok ? "OK" : "E01");
				return true;
			}

			case 'D':
				SendPacket("OK");
				return false;

			case 'k':
				return false;

			default:
				break;
		}

		// Never kill the emulator: a kill from an IDE detaches.
		if (packet == "vKill" || packet.starts_with("vKill;"))
		{
			SendPacket("OK");
			return false;
		}

		// Everything else is unsupported: vCont (gdb falls back to c/s),
		// threads, tracepoints, qOffsets...
		SendPacket("");
		return true;
	}

	namespace
	{
		bool WaitReadable(socket_t s, int timeout_ms)
		{
			fd_set set;
			FD_ZERO(&set);
			FD_SET(s, &set);
			timeval tv;
			tv.tv_sec = timeout_ms / 1000;
			tv.tv_usec = (timeout_ms % 1000) * 1000;
			return select(static_cast<int>(s) + 1, &set, nullptr, nullptr, &tv) > 0;
		}

		bool SendAll(socket_t s, std::string_view data)
		{
			while (!data.empty())
			{
#ifdef _WIN32
				const int sent = send(s, data.data(), static_cast<int>(data.size()), 0);
#else
				const ssize_t sent = send(s, data.data(), data.size(), MSG_NOSIGNAL);
#endif
				if (sent <= 0)
					return false;
				data.remove_prefix(static_cast<size_t>(sent));
			}
			return true;
		}

		socket_t OpenListener(u16 port, std::string& error)
		{
			const socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == INVALID_SOCKET_VALUE)
			{
				error = "cannot create a socket";
				return INVALID_SOCKET_VALUE;
			}
#ifndef _WIN32
			// A restarted emulator must not wait out TIME_WAIT on its own port.
			int reuse = 1;
			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
			sockaddr_in addr = {};
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			// Loopback only: whoever connects can read and write the whole machine.
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 || listen(s, 1) != 0)
			{
				error = "cannot listen on 127.0.0.1:" + std::to_string(port) + " (is the port in use?)";
				CloseSocket(s);
				return INVALID_SOCKET_VALUE;
			}
			return s;
		}

		void SleepMs(int ms)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(ms));
		}
	} // namespace

	Server::Server(Target& target, LogFunction log)
		: m_target(target)
		, m_log(std::move(log))
	{
	}

	bool Server::Alive() const
	{
		return !m_stop_requested.load(std::memory_order_acquire) && m_target.IsAlive();
	}

	void Server::Run(u16 port)
	{
#ifdef _WIN32
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			m_log("cannot initialize winsock");
			return;
		}
#endif
		socket_t listener = INVALID_SOCKET_VALUE;
		bool reported_failure = false;
		while (!m_stop_requested.load(std::memory_order_acquire))
		{
			// Listen only while there is a machine: a debugger that connects
			// before the VM exists is refused (and can retry) instead of talking
			// to a socket that answers nothing until it times out.
			if (!m_target.IsAlive())
			{
				if (listener != INVALID_SOCKET_VALUE)
				{
					CloseSocket(listener);
					listener = INVALID_SOCKET_VALUE;
				}
				SleepMs(100);
				continue;
			}

			if (listener == INVALID_SOCKET_VALUE)
			{
				std::string error;
				listener = OpenListener(port, error);
				if (listener == INVALID_SOCKET_VALUE)
				{
					if (!reported_failure)
						m_log(error);
					reported_failure = true;
					SleepMs(1000);
					continue;
				}
				reported_failure = false;
				m_log("listening on 127.0.0.1:" + std::to_string(port));
			}

			if (!WaitReadable(listener, 100))
				continue;
			const socket_t client = accept(listener, nullptr, nullptr);
			if (client == INVALID_SOCKET_VALUE)
				continue;
			int nodelay = 1;
			setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
			m_log("debugger attached");
			Serve(static_cast<intptr_t>(client));
			CloseSocket(client);
			m_log("debugger detached");
		}

		if (listener != INVALID_SOCKET_VALUE)
			CloseSocket(listener);
#ifdef _WIN32
		WSACleanup();
#endif
	}

	void Server::Serve(intptr_t client)
	{
		const socket_t s = static_cast<socket_t>(client);
		m_has_client.store(true, std::memory_order_release);
		m_target.Attached();

		// gdb's first question is why the machine stopped, so stop it.
		if (!m_target.IsHalted())
			m_target.RequestHalt();
		for (int i = 0; i < 500 && Alive() && !m_target.IsHalted(); i++)
			SleepMs(10);

		if (Alive() && m_target.IsHalted())
		{
			bool connected = true;
			Session session(m_target, [s, &connected](std::string_view bytes) {
				connected = connected && SendAll(s, bytes);
			});
			session.Begin();
			while (connected)
			{
				if (!Alive())
				{
					session.Exited();
					break;
				}
				// Poll briskly while the machine runs, so a stop is reported promptly.
				if (WaitReadable(s, session.IsRunning() ? 10 : 100))
				{
					char buffer[4096];
					const int received = static_cast<int>(recv(s, buffer, sizeof(buffer), 0));
					if (received <= 0 || !session.Receive(std::string_view(buffer, static_cast<size_t>(received))))
						break;
				}
				session.Poll();
			}
		}
		else
		{
			m_log("could not halt the machine for the debugger");
		}

		m_target.ClearAll();
		// A debugger that detached (or vanished) leaves the game running.
		if (m_target.IsAlive() && m_target.IsHalted())
			m_target.Resume();
		m_has_client.store(false, std::memory_order_release);
	}
} // namespace GdbRsp
