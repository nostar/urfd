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

#include "Global.h"
#include "DPlusClient.h"
#include "DPlusProtocol.h"

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CDplusProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
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

void CDplusProtocol::Task(void)
{
	CBuffer             Buffer;
	CIp                 Ip;
	CCallsign           Callsign;
	std::unique_ptr<CDvHeaderPacket>    Header;
	std::unique_ptr<CDvFramePacket>     Frame;

	// handle incoming packets
#if DSTAR_IPV6==true
#if DSTAR_IPV4==true
	if ( ReceiveDS(Buffer, Ip, 20) )
#else
	if ( Receive6(Buffer, Ip, 20) )
#endif
#else
	if ( Receive4(Buffer, Ip, 20) )
#endif
	{
		// crack the packet
		if ( IsValidDvFramePacket(Buffer, Frame) )
		{
			OnDvFramePacketIn(Frame, &Ip);
		}
		else if ( IsValidDvHeaderPacket(Buffer, Header) )
		{
			// is muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::dplus, Header->GetRpt2Module()) )
			{
				// handle it
				OnDvHeaderPacketIn(Header, Ip);
			}
		}
		else if ( IsValidConnectPacket(Buffer) )
		{
			std::cout << "DPlus connect request packet from " << Ip << std::endl;

			// acknowledge the request
			Send(Buffer, Ip);
		}
		else if ( IsValidLoginPacket(Buffer, &Callsign) )
		{
			std::cout << "DPlus login packet from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::dplus) )
			{
				// acknowledge the request
				EncodeLoginAckPacket(&Buffer);
				Send(Buffer, Ip);

				// create the client and append
				g_Reflector.GetClients()->AddClient(std::make_shared<CDplusClient>(Callsign, Ip));
				g_Reflector.ReleaseClients();
			}
			else
			{
				// deny the request
				EncodeLoginNackPacket(&Buffer);
				Send(Buffer, Ip);
			}

		}
		else if ( IsValidDisconnectPacket(Buffer) )
		{
			std::cout << "DPlus disconnect packet from " << Ip << std::endl;

			// find client
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::dplus);
			if ( client != nullptr )
			{
				// remove it
				clients->RemoveClient(client);
				// and acknowledge the disconnect
				EncodeDisconnectPacket(&Buffer);
				Send(Buffer, Ip);
			}
			g_Reflector.ReleaseClients();
		}
		else if ( IsValidKeepAlivePacket(Buffer) )
		{
			//std::cout << "DPlus keepalive packet from " << Ip << std::endl;

			// find all clients with that callsign & ip and keep them alive
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(Ip, EProtocol::dplus, it)) != nullptr )
			{
				client->Alive();
			}
			g_Reflector.ReleaseClients();
		}
		else
		{
			std::string title("Unknown DPlus packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep client alive
	if ( m_LastKeepaliveTime.time() > DPLUS_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CDplusProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
{
	// find the stream
	auto stream = GetStream(Header->GetStreamId());
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

		// first, check module is valid
		if ( g_Reflector.IsValidModule(rpt2.GetCSModule()) )
		{
			// find this client
			std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::dplus);
			if ( client )
			{
				// now we know if it's a dextra dongle or a genuine dplus node
				if ( Header->GetRpt2Callsign().HasSameCallsignWithWildcard(CCallsign("XRF*"))  )
				{
					client->SetDextraDongle();
				}
				// now we know its module, let's update it
				if ( !client->HasModule() )
				{
					client->SetCSModule(rpt1.GetCSModule());
				}
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
			g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, rpt2, EProtocol::dplus);
			g_Reflector.ReleaseUsers();
		}
		else
		{
			std::cout << "DPlus node " << rpt1 << " link attempt on non-existing module" << std::endl;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CDplusProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// get our sender's id
		const auto mod = packet->GetPacketModule();

		// check if it's header and update cache
		if ( packet->IsDvHeader() )
		{
			// this relies on queue feeder setting valid module id
			m_StreamsCache[mod].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet.get());
			m_StreamsCache[mod].m_iSeqCounter = 0;
		}

		// encode it
		CBuffer buffer;
		if ( EncodeDvPacket(*packet, buffer) )
		{
			// and push it to all our clients who are not streaming in
			// note that for dplus protocol, all stream of all modules are push to all clients
			// it's client who decide which stream he's interrrested in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::dplus, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() )
				{
					// check if client is a dextra dongle
					// then replace RPT2 with XRF instead of REF
					// if the client type is not yet known, send bothheaders
					if ( packet->IsDvHeader() )
					{
						// sending header in Dplus is client specific
						SendDvHeader((CDvHeaderPacket *)packet.get(), (CDplusClient *)client.get());
					}
					else if ( packet->IsDvFrame() )
					{
						// and send the DV frame
						Send(buffer, client->GetIp());

						// is it time to insert a DVheader copy ?
						if ( (m_StreamsCache[mod].m_iSeqCounter++ % 21) == 20 )
						{
							// yes, clone it
							CDvHeaderPacket packet2(m_StreamsCache[mod].m_dvHeader);
							// and send it
							SendDvHeader(&packet2, (CDplusClient *)client.get());
						}
					}
					else
					{
						// otherwise, send the original packet
						Send(buffer, client->GetIp());
					}
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}

void CDplusProtocol::SendDvHeader(CDvHeaderPacket *packet, CDplusClient *client)
{
	// encode it
	CBuffer buffer;
	if ( EncodeDvPacket(*packet, buffer) )
	{
		if ( (client->IsDextraDongle() || !client->HasModule()) )
		{
			// clone the packet and patch it
			CDvHeaderPacket packet2(*((CDvHeaderPacket *)packet));
			CCallsign rpt2 = packet2.GetRpt2Callsign();
			rpt2.PatchCallsign(0, "XRF", 3);
			packet2.SetRpt2Callsign(rpt2);

			// encode it
			CBuffer buffer2;
			if ( EncodeDvPacket(packet2, buffer2) )
			{
				// and send it
				Send(buffer2, client->GetIp());
			}

			// client type known ?
			if ( !client->HasModule() )
			{
				// no, send also the genuine packet
				Send(buffer, client->GetIp());
			}
		}
		else
		{
			// otherwise, send the original packet
			Send(buffer, client->GetIp());
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CDplusProtocol::HandleKeepalives(void)
{
	// send keepalives
	CBuffer keepalive;
	EncodeKeepAlivePacket(&keepalive);

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::dplus, it)) != nullptr )
	{
		// send keepalive
		//std::cout << "Sending DPlus packet @ " << client->GetIp() << std::endl;
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
			CBuffer disconnect;
			EncodeDisconnectPacket(&disconnect);
			Send(disconnect, client->GetIp());

			// and remove it
			std::cout << "DPlus client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}
	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CDplusProtocol::IsValidConnectPacket(const CBuffer &Buffer)
{
	uint8_t tag[] = { 0x05,0x00,0x18,0x00,0x01 };
	return (Buffer == CBuffer(tag, sizeof(tag)));
}

bool CDplusProtocol::IsValidLoginPacket(const CBuffer &Buffer, CCallsign *Callsign)
{
	uint8_t Tag[] = { 0x1C,0xC0,0x04,0x00 };
	bool valid = false;

	if ( (Buffer.size() == 28) &&(memcmp(Buffer.data(), Tag, sizeof(Tag)) == 0) )
	{
		Callsign->SetCallsign(&(Buffer.data()[4]), 8);
		valid = Callsign->IsValid();
	}
	return valid;
}

bool CDplusProtocol::IsValidDisconnectPacket(const CBuffer &Buffer)
{
	uint8_t tag[] = { 0x05,0x00,0x18,0x00,0x00 };
	return (Buffer == CBuffer(tag, sizeof(tag)));
}

bool CDplusProtocol::IsValidKeepAlivePacket(const CBuffer &Buffer)
{
	uint8_t tag[] = { 0x03,0x60,0x00 };
	return (Buffer == CBuffer(tag, sizeof(tag)));
}

bool CDplusProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	if ( 58==Buffer.size() && 0x3au==Buffer.data()[0] && 0x80u==Buffer.data()[1] && 0==memcmp(Buffer.data()+2, "DSVT", 4) && 0x10u==Buffer.data()[6] && 0x20u==Buffer.data()[10] )
	{
		// create packet
		header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket((struct dstar_header *)&(Buffer.data()[17]), *((uint16_t *)&(Buffer.data()[14])), 0x80u));
		// check validity of packet
		return ( header && header->IsValid() );
	}
	return false;
}

bool CDplusProtocol::IsValidDvFramePacket(const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &dvframe)
{
	if (0==memcmp(Buffer.data()+2, "DSVT", 4) && 0x80u==Buffer.data()[1] && 0x20u==Buffer.data()[6] && 0x20u==Buffer.data()[10])
	{
		auto size = Buffer.size();
		if (29==size && 0x1du==Buffer.data()[0])
		{
			dvframe = std::unique_ptr<CDvFramePacket>(new CDvFramePacket((SDStarFrame *)&(Buffer.data()[17]), *((uint16_t *)&(Buffer.data()[14])), Buffer.data()[16]));
			return true;
		}
		else if (32==size && 0x20u==Buffer.data()[0])
		{
			dvframe = std::unique_ptr<CDvFramePacket>(new CDvFramePacket((SDStarFrame *)&(Buffer.data()[17]), *((uint16_t *)&(Buffer.data()[14])), 0x40u | Buffer.data()[16]));
			return true;
		}
	}
	return false;
}


////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

void CDplusProtocol::EncodeKeepAlivePacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 0x03,0x60,0x00 };
	Buffer->Set(tag, sizeof(tag));
}

void CDplusProtocol::EncodeLoginAckPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 0x08,0xC0,0x04,0x00,'O','K','R','W' };
	Buffer->Set(tag, sizeof(tag));
}

void CDplusProtocol::EncodeLoginNackPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 0x08,0xC0,0x04,0x00,'B','U','S','Y' };
	Buffer->Set(tag, sizeof(tag));
}

void CDplusProtocol::EncodeDisconnectPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 0x05,0x00,0x18,0x00,0x00 };
	Buffer->Set(tag, sizeof(tag));
}


bool CDplusProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[]	= { 0x3A,0x80,0x44,0x53,0x56,0x54,0x10,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };
	struct dstar_header DstarHeader;

	Packet.ConvertToDstarStruct(&DstarHeader);

	Buffer.Set(tag, sizeof(tag));
	Buffer.Append(Packet.GetStreamId());
	Buffer.Append((uint8_t)0x80);
	Buffer.Append((uint8_t *)&DstarHeader, sizeof(struct dstar_header));

	return true;
}

bool CDplusProtocol::EncodeDvFramePacket(const CDvFramePacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[] = { 0x1D,0x80,0x44,0x53,0x56,0x54,0x20,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };

	Buffer.Set(tag, sizeof(tag));
	Buffer.Append(Packet.GetStreamId());
	if (Packet.IsLastPacket())
	{
		uint8_t tag2[] = { 0x55,0xC8,0x7A,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x25,0x1A,0xC6 };

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
