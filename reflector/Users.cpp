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


#include "Users.h"
#include "Global.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor

CUsers::CUsers() {}

////////////////////////////////////////////////////////////////////////////////////////
// users management

#define LASTHEARD_USERS_MAX_SIZE 20
void CUsers::AddUser(const CUser &user)
{
	// add
	m_Users.push_front(user);

	// if list size too big, remove oldest
	if ( m_Users.size() >= (LASTHEARD_USERS_MAX_SIZE-1) )
	{
		m_Users.resize(m_Users.size()-1);
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// operation

void CUsers::Hearing(const CCallsign &my, const CCallsign &rpt1, const CCallsign &rpt2, EProtocol protocol)
{
	Hearing(my, rpt1, rpt2, g_Reflector.GetCallsign(), protocol);
}

void CUsers::Hearing(const CCallsign &my, const CCallsign &rpt1, const CCallsign &rpt2, const CCallsign &xlx, EProtocol protocol)
{
	CUser heard(my, rpt1, rpt2, xlx);

	// first check if this user is already listed. If so, erase him.
	for ( auto it=begin(); it!=end(); it++ )
	{
		if (*it == heard)
		{
			m_Users.erase(it);
			break;
		}
	}

	AddUser(heard);

    // dashboard event
    nlohmann::json event;
    event["type"] = "hearing";
    event["my"] = my.GetCS();
    event["ur"] = rpt1.GetCS();
    event["rpt1"] = rpt2.GetCS();
    event["rpt2"] = xlx.GetCS();
    event["module"] = std::string(1, xlx.GetCSModule());
    event["protocol"] = g_GateKeeper.ProtocolName(protocol);
    g_NNGPublisher.Publish(event);
}

void CUsers::Closing(const CCallsign &my, char module, EProtocol protocol, const std::string& recording)
{
	// dashboard event
	nlohmann::json event;
	event["type"] = "closing";
	event["my"] = my.GetCS();
	event["module"] = std::string(1, module);
	event["protocol"] = g_GateKeeper.ProtocolName(protocol);
	if (!recording.empty())
		event["recording"] = recording;
	g_NNGPublisher.Publish(event);
}
