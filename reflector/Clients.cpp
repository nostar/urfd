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


#include "Global.h"
#include "Clients.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor

CClients::CClients()
{
}

////////////////////////////////////////////////////////////////////////////////////////
// destructors

CClients::~CClients()
{
	m_Mutex.lock();
	m_Clients.clear();
	m_Mutex.unlock();
}

////////////////////////////////////////////////////////////////////////////////////////
// manage Clients

void CClients::AddClient(std::shared_ptr<CClient> client)
{
	// first check if client already exists
	for ( auto it=m_Clients.begin(); it!=m_Clients.end(); it++ )
	{
		if (*client == *(*it))
		{
			// if found, just do nothing
			return;
		}
	}

	// and append
	m_Clients.push_back(client);
	std::cout << "New client " << client->GetCallsign() << " at " << client->GetIp() << " added with protocol " << client->GetProtocolName();
	if ( client->GetReflectorModule() != ' ' )
	{
		std::cout << " on module " << client->GetReflectorModule();
	}
	std::cout << std::endl;

    // dashboard event
    nlohmann::json event;
    event["type"] = "client_connect";
    event["callsign"] = client->GetCallsign().GetCS();
    event["ip"] = client->GetIp().GetAddress();
    event["protocol"] = client->GetProtocolName();
    event["module"] = std::string(1, client->GetReflectorModule());
    g_NNGPublisher.Publish(event);
}

void CClients::RemoveClient(std::shared_ptr<CClient> client)
{
	// look for the client
	for ( auto it=m_Clients.begin(); it!=m_Clients.end(); it++ )
	{
		// compare object pointers
		if ( *it == client )
		{
			// found it !
			if ( !(*it)->IsAMaster() )
			{
				// remove it
				std::cout << "Client " << (*it)->GetCallsign() << " at " << (*it)->GetIp() << " removed with protocol " << (*it)->GetProtocolName();
				if ( (*it)->GetReflectorModule() != ' ' )
				{
					std::cout << " on module " << (*it)->GetReflectorModule();
				}
				std::cout << std::endl;

                // dashboard event
                nlohmann::json event;
                event["type"] = "client_disconnect";
                event["callsign"] = (*it)->GetCallsign().GetCS();
                event["ip"] = (*it)->GetIp().GetAddress();
                event["protocol"] = (*it)->GetProtocolName();
                event["module"] = std::string(1, (*it)->GetReflectorModule());
                g_NNGPublisher.Publish(event);

				m_Clients.erase(it);
				break;
			}
		}
	}
}

bool CClients::IsClient(std::shared_ptr<CClient> client) const
{
	for ( auto it=cbegin(); it!=cend(); it++ )
	{
		if (*it == client)
			return true;
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// find Clients

std::shared_ptr<CClient> CClients::FindClient(const CIp &Ip)
{
	// find client
	for ( auto it=begin(); it!=end(); it++ )
	{
		if ( (*it)->GetIp() == Ip )
		{
			return *it;
		}
	}

	// done
	return nullptr;
}

std::shared_ptr<CClient> CClients::FindClient(const CIp &Ip, const EProtocol Protocol)
{
	// find client
	for ( auto it=begin(); it!=end(); it++ )
	{
		if ( ((*it)->GetIp() == Ip)  && ((*it)->GetProtocol() == Protocol))
		{
			return *it;
		}
	}

	// done
	return nullptr;
}

std::shared_ptr<CClient> CClients::FindClient(const CIp &Ip, const EProtocol Protocol, const char ReflectorModule)
{
	// find client
	for ( auto it=begin(); it!=end(); it++ )
	{
		if ( ((*it)->GetIp() == Ip)  && ((*it)->GetReflectorModule() == ReflectorModule) && ((*it)->GetProtocol() == Protocol) )
		{
			return *it;
		}
	}

	// done
	return nullptr;
}

std::shared_ptr<CClient> CClients::FindClient(const CCallsign &Callsign, const CIp &Ip, const EProtocol Protocol)
{
	// find client
	for ( auto it=begin(); it!=end(); it++ )
	{
		if ( (*it)->GetCallsign().HasSameCallsign(Callsign) && ((*it)->GetIp() == Ip)  && ((*it)->GetProtocol() == Protocol) )
		{
			return *it;
		}
	}

	return nullptr;
}

std::shared_ptr<CClient> CClients::FindClient(const CCallsign &Callsign, char module, const CIp &Ip, const EProtocol Protocol)
{
	// find client
	for ( auto it=begin(); it!=end(); it++ )
	{
		if ( (*it)->GetCallsign().HasSameCallsign(Callsign) && ((*it)->GetCSModule() == module) && ((*it)->GetIp() == Ip)  && ((*it)->GetProtocol() == Protocol) )
		{
			return *it;
		}
	}

	return nullptr;
}

std::shared_ptr<CClient> CClients::FindClient(const CCallsign &Callsign, const EProtocol Protocol)
{
	// find client
	for ( auto it=begin(); it!=end(); it++ )
	{
		if ( ((*it)->GetProtocol() == Protocol) && (*it)->GetCallsign().HasSameCallsign(Callsign) )
		{
			return *it;
		}
	}

	return nullptr;
}

////////////////////////////////////////////////////////////////////////////////////////
// iterate on clients

std::shared_ptr<CClient> CClients::FindNextClient(const EProtocol Protocol, std::list<std::shared_ptr<CClient>>::iterator &it)
{
	while ( it != end() )
	{
		if ( (*it)->GetProtocol() == Protocol )
		{
			return *it++;
		}
		it++;
	}
	return nullptr;
}

std::shared_ptr<CClient> CClients::FindNextClient(const CIp &Ip, const EProtocol Protocol, std::list<std::shared_ptr<CClient>>::iterator &it)
{
	while ( it != end() )
	{
		if ( ((*it)->GetProtocol() == Protocol) && ((*it)->GetIp() == Ip) )
		{
			return *it++;
		}
		it++;
	}
	return nullptr;
}

std::shared_ptr<CClient> CClients::FindNextClient(const CCallsign &Callsign, const CIp &Ip, const EProtocol Protocol, std::list<std::shared_ptr<CClient>>::iterator &it)
{
	while ( it != end() )
	{
		if ( ((*it)->GetProtocol() == Protocol) && ((*it)->GetIp() == Ip) && (*it)->GetCallsign().HasSameCallsign(Callsign) )
		{
			return *it++;
		}
		it++;
	}
	return nullptr;
}
