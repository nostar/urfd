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


#include <string.h>
#include "M17Client.h"
#include "M17Protocol.h"
#include "M17Packet.h"
#include "Global.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor
CM17Protocol::CM17Protocol() : CSEProtocol()
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
			// callsign muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::m17, Header->GetRpt2Module()) )
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
		else if ( IsValidConnectPacket(Buffer, Callsign, ToLinkModule) )
		{
			std::cout << "M17 connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::m17) && g_Reflector.IsValidModule(ToLinkModule) )
			{
				// valid module ?
				if ( g_Reflector.IsValidModule(ToLinkModule) )
				{
					// acknowledge the request
					Send("ACKN", Ip);

					// create the client and append
					g_Reflector.GetClients()->AddClient(std::make_shared<CM17Client>(Callsign, Ip, ToLinkModule));
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
		char rpt2Module = Header->GetRpt2Module(); // cache this before move

		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::m17);
		if ( client )
		{
			// get client callsign
			rpt1 = client->GetCallsign();
			// and try to open the stream
			// WARNING: OpenStream moves Header, invalidating it!
			if ( (stream = g_Reflector.OpenStream(Header, client)) != nullptr )
			{
				// keep the handle
				m_Streams[stream->GetStreamId()] = stream;
			}
		}
		// release
		g_Reflector.ReleaseClients();

		// update last heard
        CCallsign reflectorCall = rpt2;
        reflectorCall.SetCSModule(rpt2Module);
		std::cout << "DEBUG: Calling GetUsers()->Hearing for " << my.GetCS() << "..." << std::endl;
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, reflectorCall, EProtocol::m17);
		std::cout << "DEBUG: Returned from GetUsers()->Hearing" << std::endl;
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
            if (packet)
            {
                m_StreamsCache[module].m_dvHeader = *(static_cast<CDvHeaderPacket*>(packet.get()));
                m_StreamsCache[module].m_iSeqCounter = 0;
            }
		}
		else if (packet->IsDvFrame())
		{
			if (true) // Always process frames (assumes 40ms input/output match)
			{
				// Determine if we should send Legacy or Standard packets
				// Default to Legacy (true) if key missing, but Configure.cpp handles default.
				bool useLegacy = g_Configure.GetBoolean(g_Keys.m17.compat); 

				// encode it using M17Packet wrapper
				uint8_t buffer[60]; // Enough for both
				CM17Packet m17pkt(buffer, !useLegacy); 

				EncodeM17Packet(m17pkt, m_StreamsCache[module].m_dvHeader, (CDvFramePacket *)packet.get(), m_StreamsCache[module].m_iSeqCounter);

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
						m17pkt.SetDestCallsign(client->GetCallsign());

						// Calculate LICH CRC if Standard
						if (!useLegacy) {
							uint8_t *lich = m17pkt.GetLICHPointer();
							// CRC over first 28 bytes of LICH
							uint16_t l_crc = m17crc.CalcCRC(lich, 28);
							// Set CRC at offset 28 of LICH (bytes 28,29)
							// We can cast to SM17LichStandard to be safe or use set/memcpy
							((SM17LichStandard*)lich)->crc = htons(l_crc);
						}

						// set the packet crc
						// Legacy: CRC over first 52 bytes. Standard: CRC over first 54 bytes.
						uint16_t p_crc = m17crc.CalcCRC(m17pkt.GetBuffer(), m17pkt.GetSize() - 2);
						m17pkt.SetCRC(p_crc);

						// now send the packet
                        CBuffer sendBuf;
                        sendBuf.Append(m17pkt.GetBuffer(), m17pkt.GetSize());
						Send(sendBuf, client->GetIp());
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
	uint8_t tag[] = { 'P', 'O', 'N', 'G' };
	bool valid = false;
	if ( (Buffer.size() == 10) || (0 == Buffer.Compare(tag, 4)) )
	{
		callsign.CodeIn(Buffer.data() + 4);
		valid = callsign.IsValid();
	}
	return valid;
}

bool CM17Protocol::IsValidDvPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header, std::unique_ptr<CDvFramePacket> &frame)
{
	uint8_t tag[] = { 'M', '1', '7', ' ' };

	bool isStandard = false;
	bool validSize = false;
	
	if (Buffer.size() == sizeof(SM17FrameLegacy)) {
		validSize = true;
		isStandard = false;
	} else if (Buffer.size() == sizeof(SM17FrameStandard)) {
		validSize = true;
		isStandard = true;
	}

	// Buffer[19] is the low-order byte of the uint16_t frametype.
	// the 0x1CU mask (00011100 binary) just lets us see:
	// 1. the encryptions bytes (mask 0x18U) which must be zero, and
	// 2. the msb of the 2-bit payload type (mask 0x4U) which must be set. This bit set means it's voice or voice+data.
	// An masked result of 0x4U means the payload contains Codec2 voice data and there is no encryption.
	if ( validSize && (0 == Buffer.Compare(tag, sizeof(tag))) && (0x4U == (0x1CU & Buffer[19])) )
	{
		// Make the M17 header wrapper
		// Note: CM17Packet constructor copies the buffer
		CM17Packet m17(Buffer.data(), isStandard);
		
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

void CM17Protocol::EncodeM17Packet(CM17Packet &packet, const CDvHeaderPacket &Header, const CDvFramePacket *DvFrame, uint32_t iSeq) const
{
	ECodecType codec_in = Header.GetCodecIn();  // We'll need this

	// do the lich structure first
	// first, the src callsign (the lich.dest will be set in HandleQueue)
	packet.SetSourceCallsign(Header.GetMyCallsign());
	
	// then the frame type, if the incoming frame is M17 1600, then it will be Voice+Data only, otherwise Voice-Only
	packet.SetFrameType((ECodecType::c2_1600==codec_in) ? 0x7U : 0x5U);
	packet.SetNonce(DvFrame->GetNonce());

	// now the main part of the packet
	packet.SetMagic();
	
	// the frame number comes from the stream sequence counter
	// Assuming 1:1 mapping for 40ms frames (tcd output)
	uint16_t fn = iSeq % 0x8000U;
	if (DvFrame->IsLastPacket())
		fn |= 0x8000U;
	packet.SetFrameNumber(fn);
	packet.SetPayload(DvFrame->GetCodecData(ECodecType::c2_3200));
	packet.SetStreamId(Header.GetStreamId());
	// the CRC will be set in HandleQueue, after lich.dest is set
}

bool CM17Protocol::EncodeDvHeaderPacket(const CDvHeaderPacket &packet, CBuffer &buffer) const
{
	packet.EncodeInterlinkPacket(buffer);
	return true;
}

bool CM17Protocol::EncodeDvFramePacket(const CDvFramePacket &packet, CBuffer &buffer) const
{
	packet.EncodeInterlinkPacket(buffer);
	return true;
}
