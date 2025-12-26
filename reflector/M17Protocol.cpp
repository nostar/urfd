//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.
//
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


#include <string.h>
#include "M17Client.h"
#include "M17Protocol.h"
#include "M17Parrot.h"
#include "M17Packet.h"
#include "Global.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructors

CM17Protocol::CM17Protocol()
	: CSEProtocol()
{
}

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CM17Protocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
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

void CM17Protocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	CCallsign DstCallsign;
	char      ToLinkModule;
	std::unique_ptr<CDvHeaderPacket> Header;
	std::unique_ptr<CDvFramePacket>  Frame;

	// handle incoming packets
#if M17_IPV6==true
#if M17_IPV4==true
	if ( ReceiveDS(Buffer, Ip, 20) )
#else
	if ( Receive6(Buffer, Ip, 20) )
#endif
#else
	if ( Receive4(Buffer, Ip, 20) )
#endif
	{
		// crack the packet
		if ( IsValidDvPacket(Buffer, Header, Frame) )
		{
			// find client
			std::shared_ptr<CClient> client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::m17);
			bool isListen = false;
			if (client)
			{
				auto m17client = std::dynamic_pointer_cast<CM17Client>(client);
				if (m17client && m17client->IsListenOnly())
					isListen = true;
			}
			g_Reflector.ReleaseClients();

			// parrot?
            if ( Header->GetUrCallsign() == "PARROT" )
            {
                HandleParrot(Ip, Buffer, true);
            }
			// callsign muted?
			else if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::m17, Header->GetRpt2Module()) )
			{
				OnDvHeaderPacketIn(Header, Ip);

				// xrf needs a voice frame every 20 ms and an M17 frame is 40 ms, so we need a duplicate
				auto secondFrame = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(*Frame.get()));

				// This is not a second packet, so clear the last packet status, since the real last packet it the secondFrame
				if (Frame->IsLastPacket())
					Frame->SetLastPacket(false);

				// push the "first" packet
				OnDvFramePacketIn(Frame, &Ip);
				// push the "second" packet
				OnDvFramePacketIn(secondFrame, &Ip); // push two packet because we need a packet every 20 ms
			}
		}
		else if ( IsValidConnectPacket(Buffer, Callsign, ToLinkModule) || IsValidListenPacket(Buffer, Callsign, ToLinkModule) )
		{
			bool isListen = (0 == Buffer.Compare((const uint8_t*)"LSTN", 4));
			std::cout << "M17 " << (isListen ? "listen-only " : "") << "connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::m17) && g_Reflector.IsValidModule(ToLinkModule) )
			{
				// valid module ?
				if ( g_Reflector.IsValidModule(ToLinkModule) )
				{
					// acknowledge the request
					Send("ACKN", Ip);

					// create the client and append
					g_Reflector.GetClients()->AddClient(std::make_shared<CM17Client>(Callsign, Ip, ToLinkModule, isListen));
					g_Reflector.ReleaseClients();
				}
				else
				{
					std::cout << "M17 node " << Callsign << " connect attempt on non-existing module" << std::endl;

					// deny the request
					Send("NACK", Ip);
				}
			}
			else
			{
				// deny the request
				Send("NACK", Ip);
			}

		}
		else if ( IsValidDisconnectPacket(Buffer, Callsign) )
		{
			std::cout << "M17 disconnect packet from " << Callsign << " at " << Ip << std::endl;

			// find client
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::m17);
			if ( client != nullptr )
			{
				// remove it
				clients->RemoveClient(client);
				// and acknowledge the disconnect
				Send("DISC", Ip);
			}
			g_Reflector.ReleaseClients();
		}
		else if ( IsValidKeepAlivePacket(Buffer, Callsign) )
		{
			// find all clients with that callsign & ip and keep them alive
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(Callsign, Ip, EProtocol::m17, it)) != nullptr )
			{
				client->Alive();
			}
			g_Reflector.ReleaseClients();
		}
		else if ( IsValidPacketModePacket(Buffer, Callsign, DstCallsign) )
		{
			// find client
			std::shared_ptr<CClient> client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::m17);
			bool isListen = false;
			if (client)
			{
				auto m17client = std::dynamic_pointer_cast<CM17Client>(client);
				if (m17client && m17client->IsListenOnly())
					isListen = true;
			}
			g_Reflector.ReleaseClients();

			if (!isListen)
			{
                // parrot?
                if ( DstCallsign == "PARROT" )
                {
                    HandleParrot(Ip, Buffer, false);
                }
				// repeat to all clients on the module
				else if (client)
				{
					char module = client->GetReflectorModule();
					CClients *clients = g_Reflector.GetClients();
					auto it = clients->begin();
					std::shared_ptr<CClient> target = nullptr;
					while ( (target = clients->FindNextClient(EProtocol::m17, it)) != nullptr )
					{
						if (target->GetReflectorModule() == module && target->GetIp() != Ip)
						{
							Send(Buffer, target->GetIp());
						}
					}
					g_Reflector.ReleaseClients();
				}
			}
		}
		else
		{
			// invalid packet
			std::string title("Unknown M17 packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep client alive
	if ( m_LastKeepaliveTime.time() > M17_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}

    // Handle Parrot timeouts and cleanup
    for (auto it = m_ParrotMap.begin(); it != m_ParrotMap.end(); )
    {
        if (it->second->GetState() == EParrotState::record && it->second->IsExpired())
        {
            it->second->Play();
            it++;
        }
        else if (it->second->GetState() == EParrotState::done)
        {
            it = m_ParrotMap.erase(it);
        }
        else
        {
            it++;
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CM17Protocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
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
		my.SetSuffix("M17");
		CCallsign rpt1(Header->GetRpt1Callsign());
		CCallsign rpt2(Header->GetRpt2Callsign());

		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::m17);
		if ( client )
		{
			// get client callsign
			rpt1 = client->GetCallsign();
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
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, EProtocol::m17);
		g_Reflector.ReleaseUsers();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CM17Protocol::HandleQueue(void)
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
		else if (packet->IsDvFrame())
		{
			if ((1 == m_StreamsCache[module].m_iSeqCounter % 2) || packet->IsLastPacket())
			{
				// encode it
				SM17Frame frame;

				EncodeM17Packet(frame, m_StreamsCache[module].m_dvHeader, (CDvFramePacket *)packet.get(), m_StreamsCache[module].m_iSeqCounter);

				// push it to all our clients linked to the module and who are not streaming in
				CClients *clients = g_Reflector.GetClients();
				auto it = clients->begin();
				std::shared_ptr<CClient>client = nullptr;
				while ( (client = clients->FindNextClient(EProtocol::m17, it)) != nullptr )
				{
					// is this client busy ?
					if ( !client->IsAMaster() && (client->GetReflectorModule() == module) )
					{
						// set the destination
						client->GetCallsign().CodeOut(frame.lich.addr_dst);
						// set the crc
						frame.crc = htons(m17crc.CalcCRC(frame.magic, sizeof(SM17Frame)-2));
						// now send the packet
						Send(frame, client->GetIp());

					}
				}
				g_Reflector.ReleaseClients();
			}
			m_StreamsCache[module].m_iSeqCounter++;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CM17Protocol::HandleKeepalives(void)
{
	// M17 protocol sends and monitors keepalives packets
	// event if the client is currently streaming
	// so, send keepalives to all
	CBuffer keepalive;
	EncodeKeepAlivePacket(keepalive);

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::m17, it)) != nullptr )
	{
		// send keepalive
		Send(keepalive, client->GetIp());

		// is this client busy ?
		if ( client->IsAMaster() )
		{
			// yes, just tickle it
			client->Alive();
		}
		// check it's still with us
		else if ( !client->IsAlive() )
		{
			// no, disconnect
			Send("DISC", client->GetIp());

			// remove it
			std::cout << "M17 client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}

	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CM17Protocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign &callsign, char &mod)
{
	uint8_t tag[] = { 'C', 'O', 'N', 'N' };
	bool valid = false;
	if (11 == Buffer.size() && 0 == Buffer.Compare(tag, 4))
	{
		callsign.CodeIn(Buffer.data() + 4);
		mod = Buffer.data()[10];
		valid = (callsign.IsValid() && IsLetter(mod));
	}
	return valid;
}

bool CM17Protocol::IsValidListenPacket(const CBuffer &Buffer, CCallsign &callsign, char &mod)
{
	uint8_t tag[] = { 'L', 'S', 'T', 'N' };
	bool valid = false;
	if (11 == Buffer.size() && 0 == Buffer.Compare(tag, 4))
	{
		callsign.CodeIn(Buffer.data() + 4);
		mod = Buffer.data()[10];
		valid = (callsign.IsValid() && IsLetter(mod));
	}
	return valid;
}

bool CM17Protocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign &callsign)
{
	uint8_t tag[] = { 'D', 'I', 'S', 'C' };
	bool valid = false;
	if ((Buffer.size() == 10) && (0 == Buffer.Compare(tag, 4)))
	{
		callsign.CodeIn(Buffer.data() + 4);
		valid = callsign.IsValid();
	}
	return valid;
}

bool CM17Protocol::IsValidKeepAlivePacket(const CBuffer &Buffer, CCallsign &callsign)
{
	bool valid = false;
	if (Buffer.size() == 10)
	{
		if (0 == Buffer.Compare((const uint8_t*)"PING", 4) || 0 == Buffer.Compare((const uint8_t*)"PONG", 4))
		{
			callsign.CodeIn(Buffer.data() + 4);
			valid = callsign.IsValid();
		}
	}
	return valid;
}

bool CM17Protocol::IsValidPacketModePacket(const CBuffer &Buffer, CCallsign &src, CCallsign &dst)
{
	uint8_t tag[] = { 'M', '1', '7', 'P' };
	if ( (Buffer.size() >= 18) && (0 == Buffer.Compare(tag, 4)) )
	{
		dst.CodeIn(Buffer.data() + 4);
		src.CodeIn(Buffer.data() + 10);
		return (src.IsValid() && (0x0U == (0x1U & Buffer[17]))); // no encryption
	}
	return false;
}

bool CM17Protocol::IsValidDvPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header, std::unique_ptr<CDvFramePacket> &frame)
{
	uint8_t tag[] = { 'M', '1', '7', ' ' };

	if ( (Buffer.size() == sizeof(SM17Frame)) && (0 == Buffer.Compare(tag, sizeof(tag))) && (0x4U == (0x1CU & Buffer[19])) )
	{
		// Make the M17 header
		CM17Packet m17(Buffer.data());
		// get the header
		header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(m17));

		// get the frame
		frame = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(m17));

		// check validity of packets
		if ( header && header->IsValid() && frame && frame->IsValid() )
			return true;
	}
	return false;
}


////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

void CM17Protocol::EncodeKeepAlivePacket(CBuffer &Buffer)
{
	Buffer.resize(10);
	memcpy(Buffer.data(), "PING", 4);
	g_Reflector.GetCallsign().CodeOut(Buffer.data() + 4);
}

void CM17Protocol::EncodeM17Packet(SM17Frame &frame, const CDvHeaderPacket &Header, const CDvFramePacket *DvFrame, uint32_t iSeq) const
{
	ECodecType codec_in = Header.GetCodecIn();  // We'll need this


	// do the lich structure first
	// first, the src callsign (the lich.dest will be set in HandleQueue)
	CCallsign from = Header.GetMyCallsign();
	from.CodeOut(frame.lich.addr_src);
	// then the frame type, if the incoming frame is M17 1600, then it will be Voice+Data only, otherwise Voice-Only
	frame.lich.frametype = htons((ECodecType::c2_1600==codec_in) ? 0x7U : 0x5U);
	memcpy(frame.lich.nonce, DvFrame->GetNonce(), 14);

	// now the main part of the packet
	memcpy(frame.magic, "M17 ", 4);
	// the frame number comes from the stream sequence counter
	uint16_t fn = (iSeq / 2) % 0x8000U;
	if (DvFrame->IsLastPacket())
		fn |= 0x8000U;
	frame.framenumber = htons(fn);
	memcpy(frame.payload, DvFrame->GetCodecData(ECodecType::c2_3200), 16);
	frame.streamid = Header.GetStreamId();	// no host<--->network byte swapping since we never do any math on this value
	// the CRC will be set in HandleQueue, after lich.dest is set
}

bool CM17Protocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Header, CBuffer &Buffer) const
{
    (void)Header;
    (void)Buffer;
    return false; // M17 uses EncodeM17Packet
}

bool CM17Protocol::EncodeDvFramePacket(const CDvFramePacket &Frame, CBuffer &Buffer) const
{
    (void)Frame;
    (void)Buffer;
    return false; // M17 uses EncodeM17Packet
}

void CM17Protocol::HandleParrot(const CIp &Ip, const CBuffer &Buffer, bool isStream)
{
    std::string key = Ip.GetAddress();
    auto it = m_ParrotMap.find(key);
    
    if (it == m_ParrotMap.end())
    {
        std::shared_ptr<CClient> client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::m17);
        auto m17client = std::dynamic_pointer_cast<CM17Client>(client);
        g_Reflector.ReleaseClients();
        
        if (m17client)
        {
            if (isStream)
            {
                // Extract frametype from SM17Frame
                uint16_t ft = (Buffer.data()[12] << 8) | Buffer.data()[13];
                m_ParrotMap[key] = std::make_shared<CM17StreamParrot>(m17client->GetCallsign(), m17client, ft, this);
            }
            else
            {
                // Extract frametype from SM17P (lich part starts at offset 4, but frametype is at offset 16)
                uint16_t ft = (Buffer.data()[16] << 8) | Buffer.data()[17];
                m_ParrotMap[key] = std::make_shared<CM17PacketParrot>(m17client->GetCallsign(), m17client, ft, this);
            }
        }
    }
    
    it = m_ParrotMap.find(key);
    if (it != m_ParrotMap.end() && it->second->GetState() == EParrotState::record)
    {
        if (isStream)
        {
            // streamId at offset 4, fn at 38
            uint16_t sid = (Buffer.data()[4] << 8) | Buffer.data()[5];
            uint16_t fn = (Buffer.data()[38] << 8) | Buffer.data()[39];
            it->second->Add(Buffer, sid, fn);
        }
        else
        {
            it->second->AddPacket(Buffer);
            it->second->Play(); // Packet mode parrot plays back immediately
        }
    }
}
