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

#include <unordered_map>

#include "Users.h"
#include "Clients.h"
#include "Peers.h"
#include "Protocols.h"
#include "PacketStream.h"

#ifndef NO_DHT
#include "dht-values.h"
#endif


////////////////////////////////////////////////////////////////////////////////////////
// define

// event defines
#define EVENT_NONE      0
#define EVENT_CLIENTS   1
#define EVENT_USERS     2

////////////////////////////////////////////////////////////////////////////////////////
// class

class CReflector
{
public:
	CReflector();
	// destructor
	~CReflector();

	// operation
	bool Start(void);
	void Stop(void);

	// clients
	CClients *GetClients(void)                      { m_Clients.Lock(); return &m_Clients; }
	void      ReleaseClients(void)                  { m_Clients.Unlock(); }

	// peers
	CPeers   *GetPeers(void)                        { m_Peers.Lock(); return &m_Peers; }
	void      ReleasePeers(void)                    { m_Peers.Unlock(); }

	// stream opening & closing
	std::shared_ptr<CPacketStream> OpenStream(std::unique_ptr<CDvHeaderPacket> &, std::shared_ptr<CClient>);
	bool IsStreaming(char);
	void CloseStream(std::shared_ptr<CPacketStream>);

	// get
	const CCallsign &GetCallsign(void) const        { return m_Callsign; }
	CUsers  *GetUsers(void)                         { m_Users.Lock(); return &m_Users; }
	void    ReleaseUsers(void)                      { m_Users.Unlock(); }

	// check
	bool IsValidModule(char c) const                { return m_Modules.npos!=m_Modules.find(c); }

	// notifications

#ifndef NO_DHT
	void GetDHTConfig(const std::string &cs);
#endif

protected:
#ifndef NO_DHT
	// Publish DHT
	void PutDHTConfig();
#endif

	// threads
	void RouterThread(const char);
	void MaintenanceThread(void);

	// streams
	std::shared_ptr<CPacketStream> GetStream(char);
	bool IsAnyStreamOpen(void);
	bool IsStreamOpen(const std::unique_ptr<CDvHeaderPacket> &);
	char GetStreamModule(std::shared_ptr<CPacketStream>);

	// xml helpers
	void WriteXmlFile(std::ofstream &);
	void JsonReport(nlohmann::json &report);

	// identity
	CCallsign   m_Callsign;
	std::string m_Modules, m_TCmodules;

	// objects
	CUsers     m_Users;            // sorted list of lastheard stations
	CClients   m_Clients;          // list of linked repeaters/nodes/peers's modules
	CPeers     m_Peers;            // list of linked peers
	CProtocols m_Protocols;        // list of supported protocol handlers

	// queues
	std::unordered_map<char, std::shared_ptr<CPacketStream>> m_Stream;

	// threads
	std::atomic<bool> keep_running;
	std::unordered_map<char, std::future<void>> m_RouterFuture;
	std::future<void> m_MaintenanceFuture;

#ifndef NO_DHT
	// Distributed Hash Table
	dht::DhtRunner node;
	dht::InfoHash refhash;
#endif
};
