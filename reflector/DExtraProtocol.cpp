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
#include "DExtraClient.h"
#include "DExtraProtocol.h"
#

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CDextraProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
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

void CDextraProtocol::Task(void)
{
	CBuffer             Buffer;
	CIp                 Ip;
	CCallsign           Callsign;
	char                ToLinkModule;
	EProtoRev           ProtRev;
	std::unique_ptr<CDvHeaderPacket>    Header;
	std::unique_ptr<CDvFramePacket>     Frame;

	// any incoming packet ?
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
			// callsign muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::dextra, Header->GetRpt2Module()) )
			{
				OnDvHeaderPacketIn(Header, Ip);
			}
		}
		else if ( IsValidConnectPacket(Buffer, Callsign, ToLinkModule, ProtRev) )
		{
			std::cout << "DExtra connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << " rev ";
			switch (ProtRev) {
				case EProtoRev::original:
					std::cout << "Original" << std::endl;
					break;
				case EProtoRev::revised:
					std::cout << "Revised" << std::endl;
					break;
				case EProtoRev::ambe:
					std::cout << "AMBE" << std::endl;
					break;
				default:
					std::cout << "UNEXPECTED Revision" << std::endl;
					break;
			}

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::dextra) )
			{
				// valid module ?
				if ( g_Reflector.IsValidModule(ToLinkModule) )
				{
					// acknowledge the request
					EncodeConnectAckPacket(&Buffer, ProtRev);
					Send(Buffer, Ip);

					// create the client and append
					g_Reflector.GetClients()->AddClient(std::make_shared<CDextraClient>(Callsign, Ip, ToLinkModule, ProtRev));
					g_Reflector.ReleaseClients();
				}
				else
				{
					std::cout << "DExtra node " << Callsign << " connect attempt on non-existing module" << std::endl;

					// deny the request
					EncodeConnectNackPacket(&Buffer);
					Send(Buffer, Ip);
				}
			}
			else
			{
				// deny the request
				EncodeConnectNackPacket(&Buffer);
				Send(Buffer, Ip);
			}
		}
		else if ( IsValidDisconnectPacket(Buffer, &Callsign) )
		{
			std::cout << "DExtra disconnect packet from " << Callsign << " at " << Ip << std::endl;

			// find client & remove it
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::dextra);
			if ( client != nullptr )
			{
				// ack disconnect packet
				if ( client->GetProtocolRevision() == EProtoRev::revised )
				{
					EncodeDisconnectedPacket(&Buffer);
					Send(Buffer, Ip);
				}
				else if ( client->GetProtocolRevision() == EProtoRev::ambe )
				{
					Send(Buffer, Ip);
				}
				// and remove it
				clients->RemoveClient(client);
			}
			g_Reflector.ReleaseClients();
		}
		else if ( IsValidKeepAlivePacket(Buffer, &Callsign) )
		{
			//std::cout << "DExtra keepalive packet from " << Callsign << " at " << Ip << std::endl;

			// find all clients with that callsign & ip and keep them alive
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(Callsign, Ip, EProtocol::dextra, it)) != nullptr )
			{
				client->Alive();
			}
			g_Reflector.ReleaseClients();
		}
		else
		{
			std::string title("Unknown DExtra packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep alive
	if ( m_LastKeepaliveTime.time() > DEXTRA_KEEPALIVE_PERIOD )
	{
		// handle keep alives
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CDextraProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty() )
	{
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
			while ( (client = clients->FindNextClient(EProtocol::dextra, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetPacketModule()) )
				{
					// no, send the packet
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

void CDextraProtocol::HandleKeepalives(void)
{
	// DExtra protocol sends and monitors keepalives packets
	// event if the client is currently streaming
	// so, send keepalives to all
	CBuffer keepalive;
	EncodeKeepAlivePacket(&keepalive);

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::dextra, it)) != nullptr )
	{
		// send keepalive
		Send(keepalive, client->GetIp());

		// client busy ?
		if ( client->IsAMaster() )
		{
			// yes, just tickle it
			client->Alive();
		}
		// otherwise check if still with us
		else if ( !client->IsAlive() )
		{
			CPeers *peers = g_Reflector.GetPeers();
			std::shared_ptr<CPeer>peer = peers->FindPeer(client->GetCallsign(), client->GetIp(), EProtocol::dextra);
			if ( peer != nullptr && peer->GetReflectorModules()[0] == client->GetReflectorModule() )
			{
				// no, but this is a peer client, so it will be handled below
			}
			else
			{
				// no, disconnect
				CBuffer disconnect;
				EncodeDisconnectPacket(&disconnect, client->GetReflectorModule());
				Send(disconnect, client->GetIp());

				// remove it
				std::cout << "DExtra client " << client->GetCallsign() << " keepalive timeout" << std::endl;
				clients->RemoveClient(client);
			}
			g_Reflector.ReleasePeers();
		}

	}
	g_Reflector.ReleaseClients();

	// iterate on peers
	CPeers *peers = g_Reflector.GetPeers();
	auto pit = peers->begin();
	std::shared_ptr<CPeer>peer = nullptr;
	while ( (peer = peers->FindNextPeer(EProtocol::dextra, pit)) != nullptr )
	{
		// keepalives are sent between clients

		// some client busy or still with us ?
		if ( !peer->IsAMaster() && !peer->IsAlive() )
		{
			// no, disconnect all clients
			CBuffer disconnect;
			EncodeDisconnectPacket(&disconnect, peer->GetReflectorModules()[0]);
			CClients *clients = g_Reflector.GetClients();
			for ( auto cit=peer->cbegin(); cit!=peer->cend(); cit++ )
			{
				Send(disconnect, (*cit)->GetIp());
			}
			g_Reflector.ReleaseClients();

			// remove it
			std::cout << "DExtra peer " << peer->GetCallsign() << " keepalive timeout" << std::endl;
			peers->RemovePeer(peer);
		}
	}
	g_Reflector.ReleasePeers();
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CDextraProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
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
        
        // Critical Fix: Sanitize source callsign to strip suffixes (e.g. "KF8S D" -> "KF8S")
        my.SetCallsign(my.GetBase(), false);

		CCallsign rpt1(Header->GetRpt1Callsign());
		CCallsign rpt2(Header->GetRpt2Callsign());

		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::dextra);
		if ( client )
		{
			// get client callsign
			rpt1 = client->GetCallsign();
			// apply protocol revision details
			if ( client->GetProtocolRevision() == EProtoRev::ambe )
			{
				// update Header RPT2 module letter with
				// the module the client is linked to
				auto m = client->GetReflectorModule();
				Header->SetRpt2Module(m);
				rpt2.SetCSModule(m);
			}
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
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, rpt2, EProtocol::dextra);
		g_Reflector.ReleaseUsers();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CDextraProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign &callsign, char &module, EProtoRev &protrev)
{
	bool valid = false;
	if ((Buffer.size() == 11) && (Buffer.data()[9] != ' '))
	{
		callsign.SetCallsign(Buffer.data(), 8);
		callsign.SetCSModule(Buffer.data()[8]);
		module = Buffer.data()[9];
		valid = (callsign.IsValid() && IsLetter(module));
		// detect revision
		if ( (Buffer.data()[10] == 11) )
		{
			protrev = EProtoRev::revised;
		}
		else if ( callsign.HasSameCallsignWithWildcard(CCallsign("XRF*")) )
		{
			protrev = EProtoRev::ambe;
		}
		else
		{
			protrev = EProtoRev::original;
		}
	}
	return valid;
}

bool CDextraProtocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if ((Buffer.size() == 11) && (Buffer.data()[9] == ' '))
	{
		callsign->SetCallsign(Buffer.data(), 8);
		callsign->SetCSModule(Buffer.data()[8]);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CDextraProtocol::IsValidKeepAlivePacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if (Buffer.size() == 9)
	{
		callsign->SetCallsign(Buffer.data(), 8);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CDextraProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
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

bool CDextraProtocol::IsValidDvFramePacket(const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &dvframe)
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

void CDextraProtocol::EncodeKeepAlivePacket(CBuffer *Buffer)
{
	Buffer->Set(GetReflectorCallsign());
}

void CDextraProtocol::EncodeConnectPacket(CBuffer *Buffer, const char *Modules)
{
	uint8_t lm = (uint8_t)Modules[0];
	uint8_t rm = (uint8_t)Modules[1];
	Buffer->Set((uint8_t *)(const char *)GetReflectorCallsign(), CALLSIGN_LEN);
	Buffer->Append(lm);
	Buffer->Append(rm);
	Buffer->Append((uint8_t)0);
}

void CDextraProtocol::EncodeConnectAckPacket(CBuffer *Buffer, EProtoRev ProtRev)
{
	// is it for a XRF or repeater
	if ( ProtRev == EProtoRev::ambe )
	{
		// XRFxxx
		uint8_t rm = (Buffer->data())[8];
		uint8_t lm = (Buffer->data())[9];
		Buffer->clear();
		Buffer->Set((uint8_t *)m_ReflectorCallsign.GetCS().c_str(), CALLSIGN_LEN);
		Buffer->Append(lm);
		Buffer->Append(rm);
		Buffer->Append((uint8_t)0);
	}
	else
	{
		// regular repeater
		uint8_t tag[] = { 'A','C','K',0 };
		Buffer->resize(Buffer->size()-1);
		Buffer->Append(tag, sizeof(tag));
	}
}

void CDextraProtocol::EncodeConnectNackPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 'N','A','K',0 };
	Buffer->resize(Buffer->size()-1);
	Buffer->Append(tag, sizeof(tag));
}

void CDextraProtocol::EncodeDisconnectPacket(CBuffer *Buffer, char Module)
{
	uint8_t tag[] = { ' ',0 };
	Buffer->Set((uint8_t *)(const char *)GetReflectorCallsign(), CALLSIGN_LEN);
	Buffer->Append((uint8_t)Module);
	Buffer->Append(tag, sizeof(tag));
}

void CDextraProtocol::EncodeDisconnectedPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 'D','I','S','C','O','N','N','E','C','T','E','D' };
	Buffer->Set(tag, sizeof(tag));
}

bool CDextraProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Packet, CBuffer &Buffer) const
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

bool CDextraProtocol::EncodeDvFramePacket(const CDvFramePacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[] = { 'D','S','V','T',0x20,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };

	Buffer.Set(tag, sizeof(tag));
	Buffer.Append(Packet.GetStreamId());
	uint8_t id = Packet.GetDstarPacketId() % 21;
	if (Packet.IsLastPacket())
		id |= 0x40U;
	Buffer.Append(id);
	Buffer.Append((uint8_t *)Packet.GetCodecData(ECodecType::dstar), 9);
	Buffer.Append((uint8_t *)Packet.GetDvData(), 3);

	return true;

}
