//  Copyright © 2016 Jean-Luc Deltombe (LX3JL). All rights reserved.

// ulxd -- The universal reflector
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

#include "Main.h"
#include <string.h>
#include "Reflector.h"
#include "ULXPeer.h"
#include "ULXClient.h"


////////////////////////////////////////////////////////////////////////////////////////
// constructor


CUlxPeer::CUlxPeer()
{
}

CUlxPeer::CUlxPeer(const CCallsign &callsign, const CIp &ip, const char *modules, const CVersion &version)
	: CPeer(callsign, ip, modules, version)
{
	// get protocol revision
	int protrev = GetProtocolRevision(version);
	//std::cout << "Adding XLX peer with protocol revision " << protrev << std::endl;

	// and construct all xlx clients
	for ( unsigned i = 0; i < ::strlen(modules); i++ )
	{
		// create and append to vector
		m_Clients.push_back(std::make_shared<CUlxClient>(callsign, ip, modules[i], protrev));
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// status

bool CUlxPeer::IsAlive(void) const
{
	return (m_LastKeepaliveTime.time() < XLX_KEEPALIVE_TIMEOUT);
}

////////////////////////////////////////////////////////////////////////////////////////
// revision helper

int CUlxPeer::GetProtocolRevision(const CVersion &version)
{
	int protrev = XLX_PROTOCOL_REVISION_0;

	if ( version.IsEqualOrHigherTo(CVersion(2,2,0)) )
	{
		protrev = XLX_PROTOCOL_REVISION_2;
	}
	else if ( version.IsEqualOrHigherTo(CVersion(1,4,0)) )
	{
		protrev = XLX_PROTOCOL_REVISION_1;
	}
	return protrev;
}