//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.

// urfd -- The universal reflector
// Copyright © 2023 Thomas A. Early N7TAE
// Copyright © 2023 Doug McLain AD8DP
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
#include <string.h>
#include "USRPClient.h"
#include "USRPProtocol.h"

#include "Global.h"

const uint8_t USRP_TYPE_VOICE = 0;
const uint8_t USRP_TYPE_TEXT  = 2;

const uint8_t USRP_KEYUP_FALSE  = 0;
const uint8_t USRP_KEYUP_TRUE   = 1;

const uint8_t TLV_TAG_SET_INFO = 8;

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CUSRPProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	CBuffer buffer;
	m_uiStreamId = 0;
	std::ifstream file;
	std::streampos size;

	// base class, create the listing port for the read-write client
	if (! CProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	m_Module = g_Configure.GetAutolinkModule(g_Keys.usrp.module);

	// create the one special USRP Tx/Rx client
	auto scs = g_Configure.GetString(g_Keys.usrp.callsign);
	if (scs.compare("NONE"))
	{
		m_Callsign.SetCallsign(scs, false);
		CIp ip(AF_INET, uint16_t(g_Configure.GetUnsigned(g_Keys.usrp.txport)), g_Configure.GetString(g_Keys.usrp.ip).c_str());
		auto newclient = std::make_shared<CUSRPClient>(m_Callsign, ip);
		newclient->SetReflectorModule(m_Module);
		g_Reflector.GetClients()->AddClient(newclient);
		g_Reflector.ReleaseClients();
	}

	// now create "listen-only" clients, as many as specified
	if (g_Configure.Contains(g_Keys.usrp.filepath))
		file.open(g_Configure.GetString(g_Keys.usrp.filepath), std::ios::in | std::ios::binary | std::ios::ate);
	if ( file.is_open() )
	{
		// read file
		size = file.tellg();
		if ( size > 0 )
		{
			// read file into buffer
			buffer.resize((int)size+1);
			file.seekg (0, std::ios::beg);
			file.read((char *)buffer.data(), (int)size);

			// close file
			file.close();
		}
	}

	if ( buffer.size() > 0 )
	{
		char *ptr1 = (char *)buffer.data();
		char *ptr2;

		while ( (ptr2 = ::strchr(ptr1, '\n')) != nullptr )
		{
			*ptr2 = 0;
			char *ip;
			char *port;
			char *clientcs;

			if ( ((ip = ::strtok(ptr1, ";")) != nullptr) &&
				((port = ::strtok(nullptr, ";")) != nullptr) &&
				((clientcs = ::strtok(nullptr, ";")) != nullptr) )
			{
				uint16_t ui = atoi(port);
				CIp Ip(AF_INET, ui, ip);
				CCallsign cs;
				cs.SetCallsign(clientcs, false);
				auto newclient = std::make_shared<CUSRPClient>(cs, Ip);
				newclient->SetReflectorModule(m_Module);
				g_Reflector.GetClients()->AddClient(newclient);
				g_Reflector.ReleaseClients();
			}
			ptr1 = ptr2+1;
		}
	}

	// update time
	m_LastKeepaliveTime.start();

	// done
	return true;
}



////////////////////////////////////////////////////////////////////////////////////////
// task

void CUSRPProtocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	char      ToLinkModule;
	std::unique_ptr<CDvHeaderPacket> Header;
	std::unique_ptr<CDvFramePacket>  Frame;

	// handle incoming packets
#if USRP_IPV6==true
#if USRP_IPV4==true
	if ( ReceiveDS(Buffer, Ip, 20) )
#else
	if ( Receive6(Buffer, Ip, 20) )
#endif
#else
	if ( Receive4(Buffer, Ip, 20) )
#endif
	{
		// crack the packet
		if ( IsValidDvPacket(Ip, Buffer, Header, Frame) )
		{
			// push the packet
			OnDvFramePacketIn(Frame, &Ip);
		}
		else if( IsValidDvHeaderPacket(Ip, Buffer, Header) )
		{
			// callsign muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::usrp) )
			{
				OnDvHeaderPacketIn(Header, Ip);
			}
		}
		else if ( IsValidDvLastPacket(Buffer) )
		{
			// do nothing
			std::cout << "USRP_KEYUP_FALSE received" << std::endl; // DEBUG
		}
		else
		{
			// invalid packet
			std::string title("Unknown USRP packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep client alive
	if ( m_LastKeepaliveTime.time() > USRP_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CUSRPProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
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
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::usrp);
		if ( client )
		{
			// get client callsign
			rpt1 = client->GetCallsign();
			auto m = client->GetReflectorModule();
			Header->SetRpt2Module(m);
			rpt2.SetCSModule(m);
			// and try to open the stream
			if ( (stream = g_Reflector.OpenStream(Header, client)) != nullptr )
			{
				// keep the handle
				m_Streams[stream->GetStreamId()] = stream;
			}
		}
		// release
		g_Reflector.ReleaseClients();

		// update last heard
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, EProtocol::usrp);
		g_Reflector.ReleaseUsers();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CUSRPProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// get our sender's id
		const auto module = packet->GetPacketModule();
		CBuffer buffer;

		// check if it's header and update cache
		if ( packet->IsDvHeader() )
		{
			// this relies on queue feeder setting valid module id
			// m_StreamsCache[module] will be created if it doesn't exist
			m_StreamsCache[module].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet.get());
			m_StreamsCache[module].m_iSeqCounter = 0;
			EncodeUSRPHeaderPacket(m_StreamsCache[module].m_dvHeader, m_StreamsCache[module].m_iSeqCounter++, buffer);
		}
		else if ( packet->IsDvFrame() )
		{
			EncodeUSRPPacket(m_StreamsCache[module].m_dvHeader, (const CDvFramePacket &)*packet.get(), m_StreamsCache[module].m_iSeqCounter++, buffer, packet->IsLastPacket());
		}

		// send it
		if ( buffer.size() > 0 )
		{
			// and push it to all our clients linked to the module and who are not streaming in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::usrp, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() && (client->GetReflectorModule() == module) )
				{
					// no, send the packet
					Send(buffer, client->GetIp());
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CUSRPProtocol::IsValidDvPacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header, std::unique_ptr<CDvFramePacket> &frame)
{
	if(!memcmp(Buffer.data(), "USRP", 4) && (Buffer.size() == 352) && (Buffer.data()[20] == USRP_TYPE_VOICE) && (Buffer.data()[15] == USRP_KEYUP_TRUE) )
	{
		auto stream = GetStream(m_uiStreamId, &Ip);
		if ( !stream )
		{
			m_uiStreamId = static_cast<uint32_t>(::rand());
			CCallsign csMY = m_Callsign;
			CCallsign rpt1 = m_Callsign;
			CCallsign rpt2 = m_ReflectorCallsign;
			rpt1.SetCSModule(m_Module);
			rpt2.SetCSModule(' ');
			header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(csMY, CCallsign("CQCQCQ"), rpt1, rpt2, m_uiStreamId, true));
			OnDvHeaderPacketIn(header, Ip);
		}

		int16_t pcm[160];
		for(int i = 0; i < 160; ++i){
			pcm[i] = (Buffer.data()[32+(i*2)+1] << 8) | Buffer.data()[32+(i*2)];
		}

		frame = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(pcm, m_uiStreamId, false));
		return true;
	}
	return false;
}

bool CUSRPProtocol::IsValidDvHeaderPacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	if(!memcmp(Buffer.data(), "USRP", 4) && (Buffer.size() == 352) && (Buffer.data()[20] == USRP_TYPE_TEXT) && (Buffer.data()[32] == TLV_TAG_SET_INFO) ){
		auto stream = GetStream(m_uiStreamId, &Ip);
		if ( !stream )
		{
			uint32_t uiSrcId = ((Buffer.data()[1] << 16) | ((Buffer.data()[2] << 8) & 0xff00) | (Buffer.data()[3] & 0xff));
			m_uiStreamId = static_cast<uint32_t>(::rand());
			CCallsign csMY = CCallsign("", uiSrcId);
			CCallsign rpt1 = CCallsign("", uiSrcId);
			CCallsign rpt2 = m_ReflectorCallsign;
			rpt1.SetCSModule(m_Module);
			rpt2.SetCSModule(' ');
			header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(csMY, CCallsign("CQCQCQ"), rpt1, rpt2, m_uiStreamId, true));
		}
		return true;
	}
	return false;
}

bool CUSRPProtocol::IsValidDvLastPacket(const CBuffer &Buffer)
{
	if(!memcmp(Buffer.data(), "USRP", 4) && (Buffer.size() == 32) && (Buffer.data()[15] == USRP_KEYUP_FALSE) )
	{
		return true;
	}
	return false;
}

void CUSRPProtocol::EncodeUSRPHeaderPacket(const CDvHeaderPacket &Header, uint32_t iSeq, CBuffer &Buffer) const
{
	std::string cs = Header.GetMyCallsign().GetCS();
	const uint32_t cnt = htonl(iSeq);
	Buffer.resize(352);
	memset(Buffer.data(), 0, 352);
	memcpy(Buffer.data(), "USRP", 4);
	memcpy(Buffer.data() + 4, &cnt, 4);
	Buffer.data()[15] = USRP_KEYUP_FALSE;
	Buffer.data()[20] = USRP_TYPE_TEXT;
	Buffer.data()[32] = TLV_TAG_SET_INFO;
	Buffer.data()[33] = 13 + cs.size();
	memcpy(Buffer.data()+46, cs.c_str(), cs.size());
}

void CUSRPProtocol::EncodeUSRPPacket(const CDvHeaderPacket &Header, const CDvFramePacket &DvFrame, uint32_t iSeq, CBuffer &Buffer, bool islast) const
{
	if(islast)
	{
		const uint32_t cnt = htonl(iSeq);
		Buffer.resize(32);
		memset(Buffer.data(), 0, 32);
		memcpy(Buffer.data(), "USRP", 4);
		memcpy(Buffer.data() + 4, &cnt, 4);
		Buffer.data()[15] = USRP_KEYUP_FALSE;

	}
	else
	{
		std::string cs = Header.GetMyCallsign().GetCS();
		const uint32_t cnt = htonl(iSeq);
		Buffer.resize(352);
		memset(Buffer.data(), 0, 352);
		memcpy(Buffer.data(), "USRP", 4);
		memcpy(Buffer.data() + 4, &cnt, 4);
		Buffer.data()[15] = USRP_KEYUP_TRUE;
		memcpy(Buffer.data() + 32, DvFrame.GetCodecData(ECodecType::usrp), 320);
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CUSRPProtocol::HandleKeepalives(void)
{
	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::usrp, it)) != nullptr )
	{
		// is this client busy ?
		//if ( client->IsAMaster() )
		//{
			// yes, just tickle it
			client->Alive();
		//}
		// check it's still with us
		//else if ( !client->IsAlive() )
		//{
			// no, remove it
			//std::cout << "USRP client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			//clients->RemoveClient(client);
		//}

	}
	g_Reflector.ReleaseClients();
}
