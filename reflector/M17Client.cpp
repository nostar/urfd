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


#include "M17Client.h"


////////////////////////////////////////////////////////////////////////////////////////
// constructors

CM17Client::CM17Client()
	: m_IsListenOnly(false)
{
}

CM17Client::CM17Client(const CCallsign &callsign, const CIp &ip, char reflectorModule, bool isListenOnly)
	: CClient(callsign, ip, reflectorModule), m_IsListenOnly(isListenOnly)
{
}

CM17Client::CM17Client(const CM17Client &client)
	: CClient(client), m_IsListenOnly(client.m_IsListenOnly)
{
}

////////////////////////////////////////////////////////////////////////////////////////
// status

bool CM17Client::IsAlive(void) const
{
	return (m_LastKeepaliveTime.time() < M17_KEEPALIVE_TIMEOUT);
}
