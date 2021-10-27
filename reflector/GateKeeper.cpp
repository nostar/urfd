﻿//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.

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
#include "Timer.h"
#include "GateKeeper.h"

////////////////////////////////////////////////////////////////////////////////////////

CGateKeeper g_GateKeeper;


////////////////////////////////////////////////////////////////////////////////////////
// constructor

CGateKeeper::CGateKeeper()
{
	keep_running = true;
}

////////////////////////////////////////////////////////////////////////////////////////
// destructor

CGateKeeper::~CGateKeeper()
{
	Close();
}


////////////////////////////////////////////////////////////////////////////////////////
// init & clode

bool CGateKeeper::Init(void)
{

	// load lists from files
	m_NodeWhiteList.LoadFromFile(WHITELIST_PATH);
	m_NodeBlackList.LoadFromFile(BLACKLIST_PATH);
	m_PeerList.LoadFromFile(INTERLINKLIST_PATH);

	// reset run flag
	keep_running = true;

	// start  thread;
	m_Future = std::async(std::launch::async, &CGateKeeper::Thread, this);

	return true;
}

void CGateKeeper::Close(void)
{
	// kill threads
	keep_running = false;
	if ( m_Future.valid() )
	{
		m_Future.get();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// authorisations

bool CGateKeeper::MayLink(const CCallsign &callsign, const CIp &ip, int protocol, char *modules) const
{
	bool ok = true;

	switch (protocol)
	{
	// repeaters
	case PROTOCOL_DEXTRA:
	case PROTOCOL_DPLUS:
	case PROTOCOL_DCS:
	case PROTOCOL_DMRPLUS:
	case PROTOCOL_DMRMMDVM:
	case PROTOCOL_YSF:
#ifndef NO_G3
	case PROTOCOL_G3:
#endif
		// first check is IP & callsigned listed OK
		ok &= IsNodeListedOk(callsign, ip);
		// todo: then apply any protocol specific authorisation for the operation
		break;

	// XLX interlinks
	case PROTOCOL_XLX:
		ok &= IsPeerListedOk(callsign, ip, modules);
		break;

	// unsupported
	case PROTOCOL_NONE:
	default:
		ok = false;
		break;
	}

	// report
	if ( !ok )
	{
		std::cout << "Gatekeeper blocking linking of " << callsign << " @ " << ip << " using protocol " << protocol << std::endl;
	}

	// done
	return ok;
}

bool CGateKeeper::MayTransmit(const CCallsign &callsign, const CIp &ip, int protocol, char module) const
{
	bool ok = true;

	switch (protocol)
	{
	// repeaters, protocol specific
	case PROTOCOL_ANY:
	case PROTOCOL_DEXTRA:
	case PROTOCOL_DPLUS:
	case PROTOCOL_DCS:
	case PROTOCOL_DMRPLUS:
	case PROTOCOL_DMRMMDVM:
	case PROTOCOL_YSF:
#ifndef NO_G3
	case PROTOCOL_G3:
#endif
		// first check is IP & callsigned listed OK
		ok = ok && IsNodeListedOk(callsign, ip, module);
		// todo: then apply any protocol specific authorisation for the operation
		break;

	// XLX interlinks
	case PROTOCOL_XLX:
		ok = ok && IsPeerListedOk(callsign, ip, module);
		break;

	// unsupported
	case PROTOCOL_NONE:
	default:
		ok = false;
		break;
	}

	// report
	if ( !ok )
	{
		std::cout << "Gatekeeper blocking transmitting of " << callsign << " @ " << ip << " using protocol " << protocol << std::endl;
	}

	// done
	return ok;
}

////////////////////////////////////////////////////////////////////////////////////////
// thread

void CGateKeeper::Thread()
{
	while (keep_running)
	{
		// Wait 30 seconds
		for (int i=0; i<15 && keep_running; i++)
			std::this_thread::sleep_for(std::chrono::milliseconds(2000));

		// have lists files changed ?
		if ( m_NodeWhiteList.NeedReload() )
		{
			m_NodeWhiteList.ReloadFromFile();
		}
		if ( m_NodeBlackList.NeedReload() )
		{
			m_NodeBlackList.ReloadFromFile();
		}
		if ( m_PeerList.NeedReload() )
		{
			m_PeerList.ReloadFromFile();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// operation helpers

bool CGateKeeper::IsNodeListedOk(const CCallsign &callsign, const CIp &ip, char module) const
{
	bool ok = true;

	// first check IP

	// next, check callsign
	if ( ok )
	{
		// first check if callsign is in white list
		// note if white list is empty, everybody is authorized
		const_cast<CCallsignList &>(m_NodeWhiteList).Lock();
		if ( !m_NodeWhiteList.empty() )
		{
			ok = m_NodeWhiteList.IsCallsignListedWithWildcard(callsign, module);
		}
		const_cast<CCallsignList &>(m_NodeWhiteList).Unlock();

		// then check if not blacklisted
		const_cast<CCallsignList &>(m_NodeBlackList).Lock();
		ok &= !m_NodeBlackList.IsCallsignListedWithWildcard(callsign);
		const_cast<CCallsignList &>(m_NodeBlackList).Unlock();
	}

	// done
	return ok;

}

bool CGateKeeper::IsPeerListedOk(const CCallsign &callsign, const CIp &ip, char module) const
{
	bool ok = true;

	// first check IP

	// next, check callsign
	if ( ok )
	{
		// look for an exact match in the list
		const_cast<CPeerCallsignList &>(m_PeerList).Lock();
		if ( !m_PeerList.empty() )
		{
			ok = m_PeerList.IsCallsignListed(callsign, module);
		}
		const_cast<CPeerCallsignList &>(m_PeerList).Unlock();
	}

	// done
	return ok;
}

bool CGateKeeper::IsPeerListedOk(const CCallsign &callsign, const CIp &ip, char *modules) const
{
	bool ok = true;

	// first check IP

	// next, check callsign
	if ( ok )
	{
		// look for an exact match in the list
		const_cast<CPeerCallsignList &>(m_PeerList).Lock();
		if ( !m_PeerList.empty() )
		{
			ok = m_PeerList.IsCallsignListed(callsign, modules);
		}
		const_cast<CPeerCallsignList &>(m_PeerList).Unlock();
	}

	// done
	return ok;
}