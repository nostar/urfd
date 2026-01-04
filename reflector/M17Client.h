#pragma once

// urfd -- The universal reflector
// Copyright © 2021 Thomas A. Early N7TAE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "Defines.h"
#include "Client.h"

class CM17Client : public CClient
{
public:
	// constructors
	CM17Client();
	CM17Client(const CCallsign &, const CIp &, char, bool isListenOnly = false);
	CM17Client(const CM17Client &);

	// destructor
	virtual ~CM17Client() {};

	// identity
	const char *GetProtocolName(void) const     { return "M17"; }
	bool IsNode(void) const                     { return true; }
	EProtocol GetProtocol(void) const           { return EProtocol::m17; }

	// status
	bool IsAlive(void) const;
	bool IsListenOnly(void) const               { return m_IsListenOnly; }

private:
	bool m_IsListenOnly;
};

////////////////////////////////////////////////////////////////////////////////////////
