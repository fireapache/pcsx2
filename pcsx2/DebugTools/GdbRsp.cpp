// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "GdbRsp.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
static void CloseSocket(socket_t s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t INVALID_SOCKET_VALUE = -1;
static void CloseSocket(socket_t s) { close(s); }
#endif

namespace GdbRsp
{
	namespace
	{
		// gdb's mips register numbering: r0-r31, status, lo, hi, badvaddr, cause,
		// pc, f0-f31, fcsr, fir. The g packet carries them in this order.
		//
		// No target description: the PS2DEV gdb is built without XML support and
		// ignores one. It falls back to its built-in mips:5900 n32 layout, where
		// EVERY raw register is 8 bytes - the FPRs and the 32-bit control
		// registers too. So each register travels as 8 bytes, 32-bit values
		// zero-extended; `set mips fpu single` makes gdb read the FPRs as floats.
		// gdb accepts a g packet that stops at a register boundary, so the
		// registers past fir (its embedded-target extras) are simply absent.
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
		constexpr int WIRE_BYTES = 8;

		// The largest memory read answered in one packet (PacketSize below is hex
		// chars, two per byte, plus framing).
		constexpr uint32_t MAX_MEMORY_CHUNK = 0x1000;

		// The field behind a register number. Every host PCSX2 runs on is little
		// endian, which is also what gdb expects for this target, so the bytes
		// travel as they sit in memory.
		bool RegisterField(const Registers& regs, int regnum, const void*& field, int& bytes)
		{
			if (regnum >= 0 && regnum < 32)
			{
				field = &regs.gpr[regnum];
				bytes = 8;
			}
			else if (regnum >= REG_F0 && regnum < REG_F0 + 32)
			{
				field = &regs.fpr[regnum - REG_F0];
				bytes = 4;
			}
			else
			{
				switch (regnum)
				{
					case REG_STATUS: field = &regs.status; bytes = 4; break;
					case REG_LO: field = &regs.lo; bytes = 8; break;
					case REG_HI: field = &regs.hi; bytes = 8; break;
					case REG_BADVADDR: field = &regs.badvaddr; bytes = 4; break;
					case REG_CAUSE: field = &regs.cause; bytes = 4; break;
					case REG_PC: field = &regs.pc; bytes = 8; break;
					case REG_FCSR: field = &regs.fcsr; bytes = 4; break;
					case REG_FIR: field = &regs.fir; bytes = 4; break;
					default: return false;
				}
			}
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
			const uint8_t* bytes = static_cast<const uint8_t*>(data);
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
			uint8_t* bytes = static_cast<uint8_t*>(out);
			for (size_t i = 0; i < size; i++)
			{
				const int hi = HexValue(hex[i * 2]);
				const int lo = HexValue(hex[i * 2 + 1]);
				if (hi < 0 || lo < 0)
					return false;
				bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
			}
			return true;
		}

		// A whole hex number, e.g. the "1f" of "p1f". Empty or junk -> false.
		bool ParseNumber(std::string_view s, uint64_t& value)
		{
			if (s.empty() || s.size() > 16)
				return false;
			value = 0;
			for (char c : s)
			{
				const int v = HexValue(c);
				if (v < 0)
					return false;
				value = (value << 4) | static_cast<uint64_t>(v);
			}
			return true;
		}

		// "addr,len" -> both. gdb sign-extends kseg addresses for this n32 target
		// (0xffffffff80001000); the EE only has 32 address bits, so the low half
		// is the address.
		bool ParseAddressLength(std::string_view s, uint32_t& address, uint32_t& length)
		{
			const size_t comma = s.find(',');
			uint64_t a, l;
			if (comma == std::string_view::npos || !ParseNumber(s.substr(0, comma), a) ||
				!ParseNumber(s.substr(comma + 1), l) || l > 0xffffffffu)
				return false;
			address = static_cast<uint32_t>(a);
			length = static_cast<uint32_t>(l);
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

		uint8_t Checksum(std::string_view payload)
		{
			uint8_t sum = 0;
			for (char c : payload)
				sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(c));
			return sum;
		}

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

		bool SendAll(socket_t s, const char* data, size_t size)
		{
			while (size > 0)
			{
#ifdef _WIN32
				const int sent = send(s, data, static_cast<int>(size), 0);
#else
				const ssize_t sent = send(s, data, size, MSG_NOSIGNAL);
#endif
				if (sent <= 0)
					return false;
				data += sent;
				size -= static_cast<size_t>(sent);
			}
			return true;
		}

		socket_t OpenListener(uint16_t port, std::string& error)
		{
			const socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == INVALID_SOCKET_VALUE)
			{
				error = "cannot create a socket";
				return INVALID_SOCKET_VALUE;
			}
#ifndef _WIN32
			// A restarted emulator must not wait out TIME_WAIT on its own port.
			int one = 1;
			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
			sockaddr_in addr = {};
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			// Loopback only: this socket reads and writes the whole machine.
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 || listen(s, 1) != 0)
			{
				error = "cannot listen on 127.0.0.1:" + std::to_string(port) + " (port in use?)";
				CloseSocket(s);
				return INVALID_SOCKET_VALUE;
			}
			return s;
		}

		void Sleep(int ms)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(ms));
		}
	} // namespace

	std::string EncodeRegister(const Registers& regs, int regnum)
	{
		const void* field;
		int bytes;
		std::string out;
		if (!RegisterField(regs, regnum, field, bytes))
			return out;
		uint8_t wire[WIRE_BYTES] = {}; // a 32-bit register: zero-extended
		std::memcpy(wire, field, static_cast<size_t>(bytes));
		AppendHex(out, wire, sizeof(wire));
		return out;
	}

	bool DecodeRegister(std::string_view hex, int regnum, Registers& regs)
	{
		const void* field;
		int bytes;
		uint8_t wire[WIRE_BYTES];
		if (!RegisterField(regs, regnum, field, bytes) || !DecodeHex(hex, wire, sizeof(wire)))
			return false;
		std::memcpy(const_cast<void*>(field), wire, static_cast<size_t>(bytes));
		return true;
	}

	std::string EncodeRegisters(const Registers& regs)
	{
		std::string out;
		for (int i = 0; i < REG_COUNT; i++)
			out += EncodeRegister(regs, i);
		return out;
	}

	bool DecodeRegisters(std::string_view hex, Registers& regs)
	{
		// gdb may send more registers than the g reply had (its own layout is
		// longer); the ones past fir are ignored.
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

	Server::Server(Target& target, LogFn log)
		: m_target(target)
		, m_log(std::move(log))
	{
	}

	Server::~Server() = default;

	bool Server::Alive() const
	{
		return !m_stop_requested.load() && m_target.IsAlive();
	}

	void Server::Run(uint16_t port)
	{
#ifdef _WIN32
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			m_log("cannot initialise winsock");
			return;
		}
#endif
		socket_t listener = INVALID_SOCKET_VALUE;
		bool reported_failure = false;
		while (!m_stop_requested.load())
		{
			// Listen only while there is a machine: a client that connects before
			// the VM exists gets "connection refused" (the relay retries) rather
			// than a socket that answers nothing until gdb times out.
			if (!m_target.IsAlive())
			{
				if (listener != INVALID_SOCKET_VALUE)
				{
					CloseSocket(listener);
					listener = INVALID_SOCKET_VALUE;
				}
				Sleep(100);
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
					Sleep(1000);
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
			int one = 1;
			setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
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
		m_has_client.store(true);
		m_no_ack = false;
		m_rx.clear();

		// gdb's first question is why the machine is stopped, so stop it.
		if (!m_target.IsHalted())
			m_target.RequestHalt();
		for (int i = 0; i < 500 && Alive() && !m_target.IsHalted(); i++)
			Sleep(10);
		if (!Alive() || !m_target.IsHalted())
		{
			m_log("could not halt the machine for the debugger");
			m_has_client.store(false);
			return;
		}
		m_last_stop = m_target.TakeStop();
		// An attach reads as a plain stop, not "received SIGINT".
		if (m_last_stop.reason == StopReason::Interrupt)
			m_last_stop.reason = StopReason::Breakpoint;

		bool running = false;
		for (;;)
		{
			if (!Alive())
			{
				// The VM went away under the client: tell gdb the process exited.
				SendPacket(client, "W00");
				break;
			}
			std::string packet;
			if (running)
			{
				if (m_target.IsHalted())
				{
					m_last_stop = m_target.TakeStop();
					running = false;
					if (!SendPacket(client, StopReply(m_last_stop)))
						break;
					continue;
				}
				const Read read = ReadPacket(client, packet, 10);
				if (read == Read::Closed)
					break;
				if (read == Read::Interrupt)
					m_target.RequestHalt();
				// Any other packet while running would be non-stop mode, which is
				// not offered: drop it.
				continue;
			}
			const Read read = ReadPacket(client, packet, 100);
			if (read == Read::Closed)
				break;
			if (read != Read::Packet)
				continue;
			if (!Handle(client, packet, running))
				break;
		}

		m_target.ClearAll();
		// A detached (or vanished) debugger leaves the game playing.
		if (m_target.IsAlive() && m_target.IsHalted())
			m_target.Resume();
		m_has_client.store(false);
	}

	Server::Read Server::ReadPacket(intptr_t client, std::string& payload, int timeout_ms)
	{
		const socket_t s = static_cast<socket_t>(client);
		for (;;)
		{
			while (!m_rx.empty())
			{
				if (m_rx[0] == '$')
				{
					// Binary payloads escape '#', so the first one ends the packet.
					const size_t hash = m_rx.find('#');
					if (hash == std::string::npos || m_rx.size() < hash + 3)
						break; // incomplete: read more
					std::string body = m_rx.substr(1, hash - 1);
					const int hi = HexValue(m_rx[hash + 1]);
					const int lo = HexValue(m_rx[hash + 2]);
					m_rx.erase(0, hash + 3);
					const bool valid = hi >= 0 && lo >= 0 && ((hi << 4) | lo) == Checksum(body);
					if (!m_no_ack)
					{
						const char ack = valid ? '+' : '-';
						if (!SendAll(s, &ack, 1))
							return Read::Closed;
					}
					if (!valid)
						continue; // gdb resends
					payload = std::move(body);
					return Read::Packet;
				}
				const char c = m_rx[0];
				m_rx.erase(0, 1);
				if (c == '\x03')
					return Read::Interrupt;
				// '+' / '-' acks and anything between packets.
			}
			if (!WaitReadable(s, timeout_ms))
				return Read::Idle;
			char buffer[4096];
			const int received = static_cast<int>(recv(s, buffer, sizeof(buffer), 0));
			if (received <= 0)
				return Read::Closed;
			m_rx.append(buffer, static_cast<size_t>(received));
		}
	}

	bool Server::SendPacket(intptr_t client, std::string_view payload)
	{
		static constexpr char digits[] = "0123456789abcdef";
		const uint8_t sum = Checksum(payload);
		std::string framed;
		framed.reserve(payload.size() + 4);
		framed += '$';
		framed += payload;
		framed += '#';
		framed += digits[sum >> 4];
		framed += digits[sum & 0xf];
		return SendAll(static_cast<socket_t>(client), framed.data(), framed.size());
	}

	std::string Server::StopReply(const Stop& stop) const
	{
		switch (stop.reason)
		{
			case StopReason::Interrupt:
				return "T02"; // SIGINT
			case StopReason::Fault:
				return "T0b"; // SIGSEGV
			case StopReason::Watchpoint:
			{
				std::string reply = "T05";
				reply += stop.watch_kind == WatchKind::Read ? "rwatch:" : stop.watch_kind == WatchKind::Access ? "awatch:" : "watch:";
				char address[16];
				std::snprintf(address, sizeof(address), "%x", stop.data_address);
				reply += address;
				reply += ';';
				return reply;
			}
			case StopReason::Breakpoint:
			default:
				return "T05"; // SIGTRAP
		}
	}

	bool Server::Handle(intptr_t client, const std::string& p, bool& running)
	{
		const std::string_view packet(p);
		auto reply = [&](std::string_view text) { return SendPacket(client, text); };

		if (packet.empty())
			return reply("");

		if (packet == "?")
			return reply(StopReply(m_last_stop));

		if (packet.starts_with("qSupported"))
			return reply("PacketSize=4000;QStartNoAckMode+");

		if (packet == "QStartNoAckMode")
		{
			// This OK is still acknowledged; nothing after it is.
			const bool sent = reply("OK");
			m_no_ack = true;
			return sent;
		}

		if (packet == "qAttached")
			return reply("1"); // an existing process: detach, never kill

		if (packet.starts_with("qSymbol"))
			return reply("OK");

		if (packet[0] == 'H')
			return reply("OK"); // one thread of execution

		if (packet == "g")
		{
			Registers regs;
			m_target.ReadRegisters(regs);
			return reply(EncodeRegisters(regs));
		}

		if (packet[0] == 'G')
		{
			Registers regs;
			m_target.ReadRegisters(regs);
			if (!DecodeRegisters(packet.substr(1), regs))
				return reply("E01");
			m_target.WriteRegisters(regs);
			return reply("OK");
		}

		if (packet[0] == 'p')
		{
			uint64_t regnum;
			if (!ParseNumber(packet.substr(1), regnum))
				return reply("E01");
			Registers regs;
			m_target.ReadRegisters(regs);
			const std::string value = EncodeRegister(regs, static_cast<int>(regnum));
			return reply(value.empty() ? "E01" : value);
		}

		if (packet[0] == 'P')
		{
			const size_t equals = packet.find('=');
			uint64_t regnum;
			if (equals == std::string_view::npos || !ParseNumber(packet.substr(1, equals - 1), regnum))
				return reply("E01");
			Registers regs;
			m_target.ReadRegisters(regs);
			if (!DecodeRegister(packet.substr(equals + 1), static_cast<int>(regnum), regs))
				return reply("E01");
			m_target.WriteRegisters(regs);
			return reply("OK");
		}

		if (packet[0] == 'm')
		{
			uint32_t address, length;
			if (!ParseAddressLength(packet.substr(1), address, length))
				return reply("E01");
			if (length > MAX_MEMORY_CHUNK)
				length = MAX_MEMORY_CHUNK;
			std::string bytes(length, '\0');
			if (!m_target.ReadMemory(address, bytes.data(), length))
				return reply("E01");
			std::string hex;
			AppendHex(hex, bytes.data(), bytes.size());
			return reply(hex);
		}

		if (packet[0] == 'M' || packet[0] == 'X')
		{
			const size_t colon = packet.find(':');
			uint32_t address, length;
			if (colon == std::string_view::npos || !ParseAddressLength(packet.substr(1, colon - 1), address, length))
				return reply("E01");
			std::string bytes;
			if (packet[0] == 'X')
			{
				bytes = UnescapeBinary(packet.substr(colon + 1));
			}
			else
			{
				bytes.resize(length);
				if (!DecodeHex(packet.substr(colon + 1), bytes.data(), length))
					return reply("E01");
			}
			if (bytes.size() != length)
				return reply("E01");
			if (length == 0) // gdb probing for X support
				return reply("OK");
			return reply(m_target.WriteMemory(address, bytes.data(), length) ? "OK" : "E01");
		}

		if (packet[0] == 'c' || packet[0] == 'C' || packet[0] == 's' || packet[0] == 'S')
		{
			// "c[addr]" / "s[addr]" or "Csig[;addr]" / "Ssig[;addr]". The signal
			// is dropped: there is no process to deliver it to (gdb passes SIGSEGV
			// on by default, so a continue after a fault arrives as C0b).
			const bool step = packet[0] == 's' || packet[0] == 'S';
			std::string_view address_text;
			if (packet[0] == 'c' || packet[0] == 's')
				address_text = packet.substr(1);
			else if (const size_t semi = packet.find(';'); semi != std::string_view::npos)
				address_text = packet.substr(semi + 1);
			if (!address_text.empty())
			{
				uint64_t address;
				if (!ParseNumber(address_text, address))
					return reply("E01");
				Registers regs;
				m_target.ReadRegisters(regs);
				regs.pc = address;
				m_target.WriteRegisters(regs);
			}
			if (step)
				m_target.Step();
			else
				m_target.Resume();
			running = true;
			return true; // the reply is the next stop
		}

		if (packet[0] == 'Z' || packet[0] == 'z')
		{
			const bool set = packet[0] == 'Z';
			uint32_t address, length;
			if (packet.size() < 3 || packet[2] != ',' || !ParseAddressLength(packet.substr(3), address, length))
				return reply("E01");
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
					return reply("");
			}
			return reply(ok ? "OK" : "E01");
		}

		if (packet[0] == 'D')
		{
			reply("OK");
			return false;
		}

		if (packet == "vKill" || packet.starts_with("vKill;"))
		{
			// Never kill the emulator: a kill from the IDE detaches.
			reply("OK");
			return false;
		}

		if (packet == "k")
			return false;

		// Everything else is "not supported": vCont (gdb falls back to c/s),
		// threads, tracepoints, qOffsets...
		return reply("");
	}
} // namespace GdbRsp
