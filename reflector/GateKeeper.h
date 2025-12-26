//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.

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


#pragma once

#include "Defines.h"
#include "Callsign.h"
#include "IP.h"
#include "BlackWhiteSet.h"
#include "InterlinkMap.h"

////////////////////////////////////////////////////////////////////////////////////////
// class

class CGateKeeper
{
public:
	// constructor
	CGateKeeper();

	// destructor
	virtual ~CGateKeeper();

	// init & clode
	bool Init(void);
	void Close(void);

	CInterlinkMap *GetInterlinkMap(void) { m_InterlinkMap.Lock(); return &m_InterlinkMap; }
	void ReleaseInterlinkMap(void) { m_InterlinkMap.Unlock(); }

	// authorizations
	bool MayLink(const CCallsign &, const CIp &, const EProtocol, char * = nullptr) const;
	bool MayTransmit(const CCallsign &, const CIp &, EProtocol = EProtocol::any, char = ' ') const;
	const std::string ProtocolName(EProtocol) const;

protected:
	// thread
	void Thread();

	// operation helpers
	bool IsNodeListedOk(const std::string &) const;
	bool IsPeerListedOk(const std::string &, char) const;
	bool IsPeerListedOk(const std::string &, const CIp &, char *) const;

protected:
	// data
	CBlackWhiteSet m_WhiteSet, m_BlackSet;
	CInterlinkMap  m_InterlinkMap;

	// thread
	std::atomic<bool> keep_running;
	std::future<void> m_Future;
};
