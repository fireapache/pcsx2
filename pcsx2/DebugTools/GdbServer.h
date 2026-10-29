// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

// A GDB remote server for the EE, so a source-level debugger (gdb, or an IDE
// driving it) can break, inspect and continue a game running in PCSX2.
//
// Off unless a port is configured: the environment variable PCSX2_GDB_PORT
// wins, else [EmuCore] GdbServerPort in the ini; 0 or absent = off. It listens
// on 127.0.0.1 only, and only while a VM is running. The protocol itself is
// DebugTools/GdbRsp.cpp.

#include "common/Pcsx2Defs.h"

namespace GdbServer
{
	// Starts, restarts or stops the server to match the configured port.
	// CPU thread (called beside VMManager::ReloadPINE).
	void Reload();

	// CPU thread, at shutdown.
	void Shutdown();

	// From the EE's vtlb miss and bus error handlers (CPU thread). True when a
	// debugger is attached: the caller then pauses the VM and the debugger sees
	// SIGSEGV. `exact` says the caller stops ON the faulting instruction (the
	// interpreter can; the recompiler cannot).
	bool OnMemoryFault(u32 address, bool store, bool exact);
} // namespace GdbServer
