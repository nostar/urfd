//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.

// urfd -- The universal reflector
// Copyright © 2021 Thomas A. Early N7TAE
// Copyright © 2021 Doug McLain AD8DP
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


#include <string.h>
#include "P25Client.h"
#include "P25Protocol.h"

#include "Global.h"

const uint8_t REC62[] = {0x62U, 0x02U, 0x02U, 0x0CU, 0x0BU, 0x12U, 0x64U, 0x00U, 0x00U, 0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
const uint8_t REC63[] = {0x63U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC64[] = {0x64U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC65[] = {0x65U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC66[] = {0x66U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC67[] = {0x67U, 0xF0U, 0x9DU, 0x6AU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC68[] = {0x68U, 0x19U, 0xD4U, 0x26U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC69[] = {0x69U, 0xE0U, 0xEBU, 0x7BU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC6A[] = {0x6AU, 0x00U, 0x00U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
const uint8_t REC6B[] = {0x6BU, 0x02U, 0x02U, 0x0CU, 0x0BU, 0x12U, 0x64U, 0x00U, 0x00U, 0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
const uint8_t REC6C[] = {0x6CU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC6D[] = {0x6DU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC6E[] = {0x6EU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC6F[] = {0x6FU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC70[] = {0x70U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC71[] = {0x71U, 0xACU, 0xB8U, 0xA4U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC72[] = {0x72U, 0x9BU, 0xDCU, 0x75U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
const uint8_t REC73[] = {0x73U, 0x00U, 0x00U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
const uint8_t REC80[] = {0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CP25Protocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	// config data
	m_ReflectorId = g_Configure.GetUnsigned(g_Keys.p25.reflectorid);
	m_DefaultId   = g_Configure.GetUnsigned(g_Keys.mmdvm.defaultid);
	m_AutolinkModule = g_Configure.GetAutolinkModule(g_Keys.p25.autolinkmod);

	m_uiStreamId = 0;
	// base class
	if (! CProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	// update time
	m_LastKeepaliveTime.start();

	// done
	return true;
}



////////////////////////////////////////////////////////////////////////////////////////
// task

void CP25Protocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	char      ToLinkModule;
	std::unique_ptr<CDvHeaderPacket> Header;
	std::unique_ptr<CDvFramePacket>  Frame;

	// handle incoming packets
#if P25_IPV6==true
#if P25_IPV4==true
	if ( ReceiveDS(Buffer, Ip, 20) )
#else
	if ( Receive6(Buffer, Ip, 20) )
#endif
#else
	if ( Receive4(Buffer, Ip, 20) )
#endif
	{
		// crack the packet
		if ( IsValidDvPacket(Ip, Buffer, Frame) )
		{
			if( !m_uiStreamId && IsValidDvHeaderPacket(Ip, Buffer, Header) )
			{
				// callsign muted?
				if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::p25) )
				{
					OnDvHeaderPacketIn(Header, Ip);
				}
			}
			// push the packet
			OnDvFramePacketIn(Frame, &Ip);
		}
		else if ( IsValidConnectPacket(Buffer, &Callsign) )
		{
			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::p25) )
			{
				// add client if needed
				CClients *clients = g_Reflector.GetClients();
				std::shared_ptr<CClient>client = clients->FindClient(Callsign, Ip, EProtocol::p25);
				// client already connected ?
				if ( client == nullptr )
				{
					std::cout << "P25 connect packet from " << Callsign << " at " << Ip << std::endl;

					// create the client
					auto newclient = std::make_shared<CP25Client>(Callsign, Ip);

					// aautolink, if enabled
					if (' ' != m_AutolinkModule)
						newclient->SetReflectorModule(m_AutolinkModule);

					// and append
					clients->AddClient(newclient);
				}
				else
				{
					client->Alive();
				}

				// acknowledge the request -- P25Reflector simply echoes the packet
				Send(Buffer, Ip);
				// and done
				g_Reflector.ReleaseClients();
			}
		}
		else if ( IsValidDisconnectPacket(Buffer, &Callsign) )
		{
			std::cout << "P25 disconnect packet from " << Callsign << " at " << Ip << std::endl;

			// find client
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::p25);
			if ( client != nullptr )
			{
				// remove it
				clients->RemoveClient(client);
			}
			g_Reflector.ReleaseClients();
		}
		else
		{
			// invalid packet
			std::string title("Unknown P25 packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep client alive
	if ( m_LastKeepaliveTime.time() > P25_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CP25Protocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
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
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::p25);
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
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2);
		g_Reflector.ReleaseUsers();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CP25Protocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// get our sender's id
		const auto module = packet->GetPacketModule();

		// check if it's header and update cache
		if ( packet->IsDvHeader() )
		{
			// this relies on queue feeder setting valid module id
			// m_StreamsCache[module] will be created if it doesn't exist
			m_StreamsCache[module].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet.get());
			m_StreamsCache[module].m_iSeqCounter = 0;
		}
		else
		{
			// encode it
			CBuffer buffer;
			if ( packet->IsDvFrame() )
			{
				EncodeP25Packet(m_StreamsCache[module].m_dvHeader, (const CDvFramePacket &)*packet.get(), m_StreamsCache[module].m_iSeqCounter++, buffer, packet->IsLastPacket());
			}

			// send it
			if ( buffer.size() > 0 )
			{
				// and push it to all our clients linked to the module and who are not streaming in
				CClients *clients = g_Reflector.GetClients();
				auto it = clients->begin();
				std::shared_ptr<CClient>client = nullptr;
				while ( (client = clients->FindNextClient(EProtocol::p25, it)) != nullptr )
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
}


////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CP25Protocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if ( (Buffer.size() == 11) && (Buffer.data()[0] == 0xF0) )
	{
		callsign->SetCallsign(Buffer.data()+1, 10);
		valid = (callsign->IsValid());
	}
	return valid;
}

bool CP25Protocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if ( (Buffer.size() == 11) && (Buffer.data()[0] == 0xF1) )
	{
		callsign->SetCallsign(Buffer.data()+1, 10);
		valid = (callsign->IsValid());
	}
	return valid;
}

bool CP25Protocol::IsValidDvPacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &frame)
{
	if ( (Buffer.size() >= 14) )
	{
		int offset = 0;
		bool last = false;

		switch (Buffer.data()[0U]) {
		case 0x62U:
			offset = 10U;
			break;
		case 0x63U:
			offset = 1U;
			break;
		case 0x64U:
			offset = 5U;
			break;
		case 0x65U:
			offset = 5U;
			break;
		case 0x66U:
			offset = 5U;
			break;
		case 0x67U:
		case 0x68U:
		case 0x69U:
			offset = 5U;
			break;
		case 0x6AU:
			offset = 4U;
			break;
		case 0x6BU:
			offset = 10U;
			break;
		case 0x6CU:
			offset = 1U;
			break;
		case 0x6DU:
		case 0x6EU:
		case 0x6FU:
		case 0x70U:
		case 0x71U:
		case 0x72U:
			offset = 5U;
			break;
		case 0x73U:
			offset = 4U;
			break;
		case 0x80U:
			last = true;
			m_uiStreamId = 0;
			break;
		default:
			break;
		}

		frame = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(&(Buffer.data()[offset]), m_uiStreamId, last));
		return true;
	}
	return false;
}

bool CP25Protocol::IsValidDvHeaderPacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	if(Buffer.data()[0] == 0x66){
		auto stream = GetStream(m_uiStreamId, &Ip);
		if ( !stream )
		{
			uint32_t uiSrcId = ((Buffer.data()[1] << 16) | ((Buffer.data()[2] << 8) & 0xff00) | (Buffer.data()[3] & 0xff));
			m_uiStreamId = static_cast<uint32_t>(::rand());
			CCallsign csMY = CCallsign("", uiSrcId);
			CCallsign rpt1 = CCallsign("", uiSrcId);
			CCallsign rpt2 = m_ReflectorCallsign;
			rpt1.SetCSModule(P25_MODULE_ID);
			rpt2.SetCSModule(' ');
			header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(csMY, CCallsign("CQCQCQ"), rpt1, rpt2, m_uiStreamId, false));
		}
		return true;
	}
	return false;
}

void CP25Protocol::EncodeP25Packet(const CDvHeaderPacket &Header, const CDvFramePacket &DvFrame, uint32_t iSeq, CBuffer &Buffer, bool islast) const
{
	uint32_t uiSrcId = Header.GetMyCallsign().GetDmrid();

	if(uiSrcId == 0){
		uiSrcId = m_DefaultId;
	}

	if(islast)
	{
		Buffer.resize(17);
		::memcpy(Buffer.data(), REC80, 17U);
		return;
	}

	switch (iSeq % 18) {
		case 0x00U:
			Buffer.resize(22);
			::memcpy(Buffer.data(), REC62, 22U);
			::memcpy(Buffer.data() + 10U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x01U:
			Buffer.resize(14);
			::memcpy(Buffer.data(), REC63, 14U);
			::memcpy(Buffer.data() + 1U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x02U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC64, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x03U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC65, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			Buffer.data()[1U] = (m_ReflectorId >> 16) & 0xFFU;
			Buffer.data()[2U] = (m_ReflectorId >> 8) & 0xFFU;
			Buffer.data()[3U] = (m_ReflectorId >> 0) & 0xFFU;
			break;
		case 0x04U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC66, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			Buffer.data()[1U] = (uiSrcId >> 16) & 0xFFU;
			Buffer.data()[2U] = (uiSrcId >> 8) & 0xFFU;
			Buffer.data()[3U] = (uiSrcId >> 0) & 0xFFU;
			break;
		case 0x05U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC67, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x06U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC68, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x07U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC69, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x08U:
			Buffer.resize(16);
			::memcpy(Buffer.data(), REC6A, 16U);
			::memcpy(Buffer.data() + 4U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x09U:
			Buffer.resize(22);
			::memcpy(Buffer.data(), REC6B, 22U);
			::memcpy(Buffer.data() + 10U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x0AU:
			Buffer.resize(14);
			::memcpy(Buffer.data(), REC6C, 14U);
			::memcpy(Buffer.data() + 1U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x0BU:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC6D, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x0CU:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC6E, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x0DU:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC6F, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x0EU:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC70, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x0FU:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC71, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x10U:
			Buffer.resize(17);
			::memcpy(Buffer.data(), REC72, 17U);
			::memcpy(Buffer.data() + 5U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		case 0x11U:
			Buffer.resize(16);
			::memcpy(Buffer.data(), REC73, 16U);
			::memcpy(Buffer.data() + 4U, DvFrame.GetCodecData(ECodecType::p25), 11U);
			break;
		}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CP25Protocol::HandleKeepalives(void)
{
	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::p25, it)) != nullptr )
	{
		// is this client busy ?
		if ( client->IsAMaster() )
		{
			// yes, just tickle it
			client->Alive();
		}
		// check it's still with us
		else if ( !client->IsAlive() )
		{
			// no, remove it
			std::cout << "P25 client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}

	}
	g_Reflector.ReleaseClients();
}
