//  Copyright © 2019 Marius Petrescu (YO2LOJ). All rights reserved.

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

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/stat.h>

#include "Global.h"
#include "G3Client.h"
#include "G3Protocol.h"


////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CG3Protocol::Initialize(const char */*type*/, const EProtocol /*type*/, const uint16_t /*port*/, const bool /*has_ipv4*/, const bool /*has_ipv6*/)
// everything is hard coded until ICOM gets their act together and start supporting IPv6
{
	//config data
	m_TerminalPath.assign(g_Configure.GetString(g_Keys.files.terminal));
	const std::string ipv4address(g_Configure.GetString(g_Keys.ip.ipv4bind));

	ReadOptions();

	// init reflector apparent callsign
	m_ReflectorCallsign = g_Reflector.GetCallsign();

	// reset stop flag
	keep_running = true;

	// update the reflector callsign
	//m_ReflectorCallsign.PatchCallsign(0, "XLX", 3);

	// create our sockets
	CIp ip(AF_INET, G3_DV_PORT, ipv4address.c_str());
	if ( ip.IsSet() )
	{
		if (! m_Socket4.Open(ip))
			return false;
	}
	else
		return false;

	std::cout << "Listening on " << ip << std::endl;

	//create helper socket
	ip.SetPort(G3_PRESENCE_PORT);
	if (! m_PresenceSocket.Open(ip))
	{
		std::cerr << "Error opening socket on port UDP" << G3_PRESENCE_PORT << " on ip " << ip << std::endl;
		return false;
	}

	ip.SetPort(G3_CONFIG_PORT);
	if (! m_ConfigSocket.Open(ip))
	{
		std::cerr << "Error opening G3 config socket on port UDP" << G3_CONFIG_PORT << " on ip " << ip << std::endl;
		return false;
	}

	if (! m_IcmpRawSocket.Open(IPPROTO_ICMP))
	{
		std::cerr << "Error opening raw socket for ICMP" << std::endl;
		return false;
	}

	// start helper threads
	m_Future         = std::async(std::launch::async, &CG3Protocol::Thread, this);
	m_PresenceFuture = std::async(std::launch::async, &CG3Protocol::PresenceThread, this);
	m_ConfigFuture   = std::async(std::launch::async, &CG3Protocol::ConfigThread, this);
	m_IcmpFuture     = std::async(std::launch::async, &CG3Protocol::IcmpThread, this);

	// update time
	m_LastKeepaliveTime.start();

	std::cout << "Initialized G3 Protocol, all threads started" << std::endl;
	return true;
}

void CG3Protocol::Close(void)
{
	if (m_PresenceFuture.valid())
	{
		m_PresenceFuture.get();
	}

	if (m_ConfigFuture.valid())
	{
		m_ConfigFuture.get();
	}

	if (m_IcmpFuture.valid())
	{
		m_IcmpFuture.get();
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// private threads

void CG3Protocol::PresenceThread()
{
	while (keep_running)
	{
		PresenceTask();
	}
}

void CG3Protocol::ConfigThread()
{
	while (keep_running)
	{
		ConfigTask();
	}
}

void CG3Protocol::IcmpThread()
{
	while (keep_running)
	{
		IcmpTask();
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// presence task

void CG3Protocol::PresenceTask(void)
{
	CBuffer             Buffer;
	CIp                 ReqIp;
	CCallsign           Callsign;
	CCallsign           Owner;
	CCallsign           Terminal;


	if ( m_PresenceSocket.Receive(Buffer, ReqIp, 20) )
	{

		CIp Ip(ReqIp);
		Ip.SetPort(G3_DV_PORT);

		if (Buffer.size() == 32)
		{
			Callsign.SetCallsign(&Buffer.data()[8], 8);
			Owner.SetCallsign(&Buffer.data()[16], 8);
			Terminal.SetCallsign(&Buffer.data()[24], 8);

			std::cout << "Presence from owner " << Owner << " on " << Ip << " as " << Callsign << " on terminal " << Terminal << std::endl;

			// accept
			Buffer.data()[2] = 0x80; // response
			Buffer.data()[3] = 0x00; // ok

			if (m_GwAddress == 0)
			{
				Buffer.Append(*(uint32_t *)m_ConfigSocket.GetLocalAddr());
			}
			else
			{
				Buffer.Append(m_GwAddress);
			}

			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>extant = nullptr;
			while ( (extant = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
			{
				CIp ClIp = extant->GetIp();
				if (ClIp.GetAddr() == Ip.GetAddr())
				{
					break;
				}
			}

			if (extant == nullptr)
			{
				it = clients->begin();

				// do we already have a client with the same call (IP changed)?
				while ( (extant = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
				{
					if (extant->GetCallsign().HasSameCallsign(Terminal))
					{
						//delete old client
						clients->RemoveClient(extant);
						break;
					}
				}

				// create new client and append
				clients->AddClient(std::make_shared<CG3Client>(Terminal, Ip));
			}
			else
			{
				// client changed callsign
				if (!extant->GetCallsign().HasSameCallsign(Terminal))
				{
					//delete old client
					clients->RemoveClient(extant);

					// create new client and append
					clients->AddClient(std::make_shared<CG3Client>(Terminal, Ip));
				}
			}
			g_Reflector.ReleaseClients();

			m_PresenceSocket.Send(Buffer, ReqIp);
		}
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// configuration task

void CG3Protocol::ConfigTask(void)
{
	CBuffer             Buffer;
	CIp                 Ip;
	CCallsign           Call;
	bool                isRepeaterCall;

	if ( m_ConfigSocket.Receive(&Buffer, &Ip, 20) != -1 )
	{
		if (Buffer.size() == 16)
		{
			if (memcmp(&Buffer.data()[8], "        ", 8) == 0)
			{
				Call = GetReflectorCallsign();
			}
			else
			{
				Call.SetCallsign(&Buffer.data()[8], 8);
			}

			isRepeaterCall = ((Buffer.data()[2] & 0x10) == 0x10);

			std::cout << "Config request from " << Ip << " for " << Call << " (" << ((char *)(isRepeaterCall)?"repeater":"routed") << ")" << std::endl;

			//std::cout << "Local address: " << inet_ntoa(*m_ConfigSocket.GetLocalAddr()) << std::endl;

			Buffer.data()[2] |= 0x80; // response

			if (isRepeaterCall)
			{
				if ((Call.HasSameCallsign(GetReflectorCallsign())) && (g_Reflector.IsValidModule(Call.GetCSModule())))
				{
					Buffer.data()[3] = 0x00; // ok
				}
				else
				{
					std::cout << "Module " << Call << " invalid" << std::endl;
					Buffer.data()[3] = 0x01; // reject
				}
			}
			else
			{
				// reject routed calls for now
				Buffer.data()[3] = 0x01; // reject
			}

			char module = Call.GetCSModule();

			if (!strchr(m_Modules.c_str(), module) && !strchr(m_Modules.c_str(), '*'))
			{
				// restricted
				std::cout << "Module " << Call << " restricted by configuration" << std::endl;
				Buffer.data()[3] = 0x01; // reject
			}

			// UR
			Buffer.resize(8);
			Buffer.Append((uint8_t *)(const char *)Call, CALLSIGN_LEN - 1);
			Buffer.Append((uint8_t)module);

			// RPT1
			Buffer.Append((uint8_t *)(const char *)GetReflectorCallsign(), CALLSIGN_LEN - 1);
			Buffer.Append((uint8_t)'G');

			// RPT2
			Buffer.Append((uint8_t *)(const char *)GetReflectorCallsign(), CALLSIGN_LEN - 1);

			if (isRepeaterCall)
			{
				Buffer.Append((uint8_t)Call.GetCSModule());
			}
			else
			{
				// routed - no module for now
				Buffer.Append((uint8_t)' ');
			}

			if (Buffer.data()[3] == 0x00)
			{
				std::cout << "External G3 gateway address " << inet_ntoa(*(in_addr *)&m_GwAddress) << std::endl;

				if (m_GwAddress == 0)
				{
					Buffer.Append(*(uint32_t *)m_ConfigSocket.GetLocalAddr());
				}
				else
				{
					Buffer.Append(m_GwAddress);
				}
			}
			else
			{
				Buffer.Append(0u);
			}

			m_ConfigSocket.Send(Buffer, Ip);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// icmp task

void CG3Protocol::IcmpTask(void)
{
	uint8_t Buffer[RAW_BUFFER_LENMAX];
	CIp Ip;
	int iIcmpType;

	if ((iIcmpType = m_IcmpRawSocket.IcmpReceive(Buffer, &Ip, 20)) != -1)
	{
		if (iIcmpType == ICMP_DEST_UNREACH)
		{
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
			{
				CIp ClientIp = client->GetIp();
				if (ClientIp.GetAddr() == Ip.GetAddr())
				{
					clients->RemoveClient(client);
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// DV task

void CG3Protocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	char      ToLinkModule;
	int       ProtRev;
	std::unique_ptr<CDvHeaderPacket>    Header;
	std::unique_ptr<CDvFramePacket>     Frame;

	// any incoming packet ?
	if ( m_Socket4.Receive(Buffer, Ip, 20) )
	{
		CIp ClIp;
		CIp *BaseIp = nullptr;
		CClients *clients = g_Reflector.GetClients();
		auto it = clients->begin();
		std::shared_ptr<CClient>client = nullptr;
		while ( (client = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
		{
			ClIp = client->GetIp();
			if (ClIp.GetAddr() == Ip.GetAddr())
			{
				BaseIp = &ClIp;
				client->Alive();
				// suppress host checks - no ping needed to trigger potential ICMPs
				// the regular data flow will do it
				m_LastKeepaliveTime.start();
				break;
			}
		}
		g_Reflector.ReleaseClients();

		if (BaseIp != nullptr)
		{
			// crack the packet
			if ( IsValidDvFramePacket(Buffer, Frame) )
			{
				OnDvFramePacketIn(Frame, BaseIp);
			}
			else if ( IsValidDvHeaderPacket(Buffer, Header) )
			{
				// callsign muted?
				if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::g3, Header->GetRpt2Module()) )
				{
					// handle it
					OnDvHeaderPacketIn(Header, *BaseIp);
				}
			}
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep alive during idle if needed
	if ( m_LastKeepaliveTime.time() > G3_KEEPALIVE_PERIOD )
	{
		// handle keep alives
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();

		// reload option if needed - called once every G3_KEEPALIVE_PERIOD
		NeedReload();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CG3Protocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// suppress host checks
		m_LastKeepaliveTime.start();

		// get the packet
		auto packet = m_Queue.Pop();

		// encode it
		CBuffer buffer;
		if ( EncodeDvPacket(*packet, buffer) )
		{
			// and push it to all our clients linked to the module and who are not streaming in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetPacketModule()) )
				{
					// not busy, send the packet
					int n = packet->IsDvHeader() ? 5 : 1;
					for ( int i = 0; i < n; i++ )
					{
						Send(buffer, client->GetIp());
					}
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CG3Protocol::HandleKeepalives(void)
{
	// G3 Terminal mode does not support keepalive
	// We will send some short packed and expect
	// A ICMP unreachable on failure
	CBuffer keepalive((uint8_t *)"PING", 4);

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
	{
		if (!client->IsAlive())
		{
			clients->RemoveClient(client);
		}
		else
		{
			// send keepalive packet
			Send(keepalive, client->GetIp());
		}
	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CG3Protocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
{
	// find the stream
	auto stream = GetStream(Header->GetStreamId(), &Ip);

	if ( stream )
	{
		// stream already open
		// skip packet, but tickle the stream
		stream->Tickle();
	}
	else
	{
		// no stream open yet, open a new one
		CCallsign my(Header->GetMyCallsign());
		CCallsign rpt1(Header->GetRpt1Callsign());
		CCallsign rpt2(Header->GetRpt2Callsign());

		// find this client
		CClients *clients = g_Reflector.GetClients();
		auto it = clients->begin();
		std::shared_ptr<CClient>client = nullptr;
		while ( (client = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
		{
			CIp ClIp = client->GetIp();
			if (ClIp.GetAddr() == Ip.GetAddr())
			{
				break;
			}
		}

		if ( client )
		{

			// move it to the proper module
			if (m_ReflectorCallsign.HasSameCallsign(rpt2))
			{
				if (client->GetReflectorModule() != rpt2.GetCSModule())
				{
					auto new_module = rpt2.GetCSModule();
					if (strchr(m_Modules.c_str(), '*') || strchr(m_Modules.c_str(), new_module))
					{
						client->SetReflectorModule(new_module);
					}
					else
					{
						g_Reflector.ReleaseClients();
						return;
					}
				}

				// get client callsign
				rpt1 = client->GetCallsign();

				// and try to open the stream
				if ( (stream = g_Reflector.OpenStream(Header, client)) != nullptr )
				{
					// keep the handle
					m_Streams[stream->GetStreamId()] = stream;
				}

				// update last heard
				g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, EProtocol::g3);
				g_Reflector.ReleaseUsers();
			}
		}
		// release
		g_Reflector.ReleaseClients();
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CG3Protocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	if ( 56==Buffer.size() && 0==Buffer.Compare((uint8_t *)"DSVT", 4) && 0x10U==Buffer.data()[4] && 0x20U==Buffer.data()[8] )
	{
		// create packet
		header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket((struct dstar_header *)&(Buffer.data()[15]), *((uint16_t *)&(Buffer.data()[12])), 0x80));
		// check validity of packet
		if ( header && header->IsValid() )
			return true;
	}
	return false;
}

bool CG3Protocol::IsValidDvFramePacket(const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &dvframe)
{
	if ( 27==Buffer.size() && 0==Buffer.Compare((uint8_t *)"DSVT", 4) && 0x20U==Buffer.data()[4] && 0x20U==Buffer.data()[8] )
	{
		// create packet
		dvframe = std::unique_ptr<CDvFramePacket>(new CDvFramePacket((SDStarFrame *)&(Buffer.data()[15]), *((uint16_t *)&(Buffer.data()[12])), Buffer.data()[14]));
		// check validity of packet
		if ( dvframe && dvframe->IsValid() )
			return true;
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

bool CG3Protocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[]	= { 'D','S','V','T',0x10,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };
	struct dstar_header DstarHeader;

	Packet.ConvertToDstarStruct(&DstarHeader);

	Buffer.Set(tag, sizeof(tag));
	Buffer.Append(Packet.GetStreamId());
	Buffer.Append((uint8_t)0x80);
	Buffer.Append((uint8_t *)&DstarHeader, sizeof(struct dstar_header));

	return true;
}

bool CG3Protocol::EncodeDvFramePacket(const CDvFramePacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[] = { 'D','S','V','T',0x20,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };

	Buffer.Set(tag, sizeof(tag));
	Buffer.Append(Packet.GetStreamId());
	if (Packet.IsLastPacket())
	{
		uint8_t tag2[] = { 0x55,0xC8,0x7A,0x00,0x00,0x00,0x00,0x00,0x00,0x25,0x1A,0xC6 };

		Buffer.Append((uint8_t)((Packet.GetPacketId() % 21) | 0x40));
		Buffer.Append(tag2, sizeof(tag2));
	}
	else
	{
		Buffer.Append((uint8_t)(Packet.GetPacketId() % 21));
		Buffer.Append((uint8_t *)Packet.GetCodecData(ECodecType::dstar), 9);
		Buffer.Append((uint8_t *)Packet.GetDvData(), 3);
	}

	return true;

}

////////////////////////////////////////////////////////////////////////////////////////
// option helpers

char *CG3Protocol::TrimWhiteSpaces(char *str)
{
	char *end;
	while ((*str == ' ') || (*str == '\t')) str++;
	if (*str == 0)
		return str;
	end = str + strlen(str) - 1;
	while ((end > str) && ((*end == ' ') || (*end == '\t') || (*end == '\r')))
		end--;
	*(end + 1) = 0;
	return str;
}


void CG3Protocol::NeedReload(void)
{
	struct stat fileStat;

	if (::stat(m_TerminalPath.c_str(), &fileStat) != -1)
	{
		if (m_LastModTime != fileStat.st_mtime)
		{
			ReadOptions();

			// we have new options - iterate on clients for potential removal
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::g3, it)) != nullptr )
			{
				char module = client->GetReflectorModule();
				if (!strchr(m_Modules.c_str(), module) && !strchr(m_Modules.c_str(), '*'))
				{
					clients->RemoveClient(client);
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}

void CG3Protocol::ReadOptions(void)
{
	char sz[256];
	int opts = 0;


	std::ifstream file(m_TerminalPath.c_str());
	if (file.is_open())
	{
		m_GwAddress = 0u;
		m_Modules = "*";

		while (file.getline(sz, sizeof(sz)).good())
		{
			char *szt = TrimWhiteSpaces(sz);
			char *szval;

			if ((::strlen(szt) > 0) && szt[0] != '#')
			{
				if ((szt = ::strtok(szt, " ,\t")) != nullptr)
				{
					if ((szval = ::strtok(nullptr, " ,\t")) != nullptr)
					{
						if (::strncmp(szt, "address", 7) == 0)
						{
							in_addr addr = { .s_addr = inet_addr(szval) };
							if (addr.s_addr)
							{
								std::cout << "G3 handler address set to " << inet_ntoa(addr) << std::endl;
								m_GwAddress = addr.s_addr;
								opts++;
							}
						}
						else if (strncmp(szt, "modules", 7) == 0)
						{
							std::cout << "G3 handler module list set to " << szval << std::endl;
							m_Modules = szval;
							opts++;
						}
						else
						{
							// unknown option - ignore
						}
					}
				}
			}
		}
		std::cout << "G3 handler loaded " << opts << " options from file " << m_TerminalPath << std::endl;
		file.close();

		struct stat fileStat;

		if (::stat(m_TerminalPath.c_str(), &fileStat) != -1)
		{
			m_LastModTime = fileStat.st_mtime;
		}
	}
}
