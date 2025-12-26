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

#include "BMPeer.h"
#include "BMProtocol.h"
#include "Global.h"

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CBMProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	m_HasTranscoder = (0 != g_Configure.GetUnsigned(g_Keys.tc.port));
	if (! CProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	// update time
	m_LastKeepaliveTime.start();
	m_LastPeersLinkTime.start();

	// done
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////
// task

void CBMProtocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	char      Modules[27];
	CVersion  Version;
	std::unique_ptr<CDvHeaderPacket>    Header;
	std::unique_ptr<CDvFramePacket>     Frame;

	// any incoming packet ?
#if XLX_IPV6==true
#if XLX_IPV4==true
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
			// callsign allowed?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip) )
			{
				OnDvHeaderPacketIn(Header, Ip);
			}
		}
		else if ( IsValidConnectPacket(Buffer, &Callsign, Modules, &Version) )
		{
			std::cout << "XLX (" << Version.GetMajor() << "." << Version.GetMinor() << "." << Version.GetRevision() << ") connect packet for modules " << Modules << " from " << Callsign <<  " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::bm, Modules) )
			{
				// acknowledge the request
				EncodeConnectAckPacket(&Buffer, Modules);
				Send(Buffer, Ip);
			}
			else
			{
				// deny the request
				EncodeConnectNackPacket(&Buffer);
				Send(Buffer, Ip);
			}
		}
		else if ( IsValidAckPacket(Buffer, &Callsign, Modules, &Version)  )
		{
			std::cout << "XLX ack packet for modules " << Modules << " from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::bm, Modules) )
			{
				// already connected ?
				CPeers *peers = g_Reflector.GetPeers();
				if ( peers->FindPeer(Callsign, Ip, EProtocol::bm) == nullptr )
				{
					// create the new peer
					// this also create one client per module
					std::shared_ptr<CPeer>peer = std::make_shared<CBmPeer>(Callsign, Ip, Modules, Version);

					// append the peer to reflector peer list
					// this also add all new clients to reflector client list
					peers->AddPeer(peer);
				}
				g_Reflector.ReleasePeers();
			}
		}
		else if ( IsValidDisconnectPacket(Buffer, &Callsign) )
		{
			std::cout << "XLX disconnect packet from " << Callsign << " at " << Ip << std::endl;

			// find peer
			CPeers *peers = g_Reflector.GetPeers();
			std::shared_ptr<CPeer>peer = peers->FindPeer(Ip, EProtocol::bm);
			if ( peer != nullptr )
			{
				// remove it from reflector peer list
				// this also remove all concerned clients from reflector client list
				// and delete them
				peers->RemovePeer(peer);
			}
			g_Reflector.ReleasePeers();
		}
		else if ( IsValidNackPacket(Buffer, &Callsign) )
		{
			std::cout << "XLX nack packet from " << Callsign << " at " << Ip << std::endl;
		}
		else if ( IsValidKeepAlivePacket(Buffer, &Callsign) )
		{
			//std::cout << "XLX keepalive packet from " << Callsign << " at " << Ip << std::endl;

			// find peer
			CPeers *peers = g_Reflector.GetPeers();
			std::shared_ptr<CPeer>peer = peers->FindPeer(Ip, EProtocol::bm);
			if ( peer != nullptr )
			{
				// keep it alive
				peer->Alive();
			}
			g_Reflector.ReleasePeers();
		}
		else
		{
			std::string title("Unknown XLX packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep alive
	if ( m_LastKeepaliveTime.time() > BM_KEEPALIVE_PERIOD )
	{
		// handle keep alives
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}

	// peer connections
	if ( m_LastPeersLinkTime.time() > BM_RECONNECT_PERIOD )
	{
		// handle remote peers connections
		HandlePeerLinks();

		// update time
		m_LastPeersLinkTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CBMProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// encode it
		CBuffer buffer;
		if ( EncodeDvPacket(*packet, buffer) )
		{
			// encode revision dependent version
			CBuffer bufferLegacy = buffer;
			if ( packet->IsDvFrame() && (bufferLegacy.size() == 45) )
			{
				bufferLegacy.resize(27);
			}

			// and push it to all our clients linked to the module and who are not streaming in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::bm, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetPacketModule()) )
				{
					// no, send the packet
					// this is protocol revision dependent
					switch ( client->GetProtocolRevision() )
					{
					case EProtoRev::original:
					case EProtoRev::revised:
						Send(bufferLegacy, client->GetIp());
						break;
					case EProtoRev::ambe:
					default:
						if (m_HasTranscoder)
							Send(buffer, client->GetIp());
						else
							Send(bufferLegacy, client->GetIp());
						break;
					}
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CBMProtocol::HandleKeepalives(void)
{
	// DExtra protocol sends and monitors keepalives packets
	// event if the client is currently streaming
	// so, send keepalives to all
	CBuffer keepalive;
	EncodeKeepAlivePacket(&keepalive);

	// iterate on peers
	CPeers *peers = g_Reflector.GetPeers();
	auto pit = peers->begin();
	std::shared_ptr<CPeer>peer = nullptr;
	while ( (peer = peers->FindNextPeer(EProtocol::bm, pit)) != nullptr )
	{
		// send keepalive
		Send(keepalive, peer->GetIp());

		// client busy ?
		if ( peer->IsAMaster() )
		{
			// yes, just tickle it
			peer->Alive();
		}
		// otherwise check if still with us
		else if ( !peer->IsAlive() )
		{
			// no, disconnect
			CBuffer disconnect;
			EncodeDisconnectPacket(&disconnect);
			Send(disconnect, peer->GetIp());

			// remove it
			std::cout << "BM peer " << peer->GetCallsign() << " keepalive timeout" << std::endl;
			peers->RemovePeer(peer);
		}
	}
	g_Reflector.ReleasePeers();
}

////////////////////////////////////////////////////////////////////////////////////////
// Peers helpers

void CBMProtocol::HandlePeerLinks(void)
{
	CBuffer buffer;

	// get the list of peers
	auto ilmap = g_GateKeeper.GetInterlinkMap();
	CPeers *peers = g_Reflector.GetPeers();

	// check if all our connected peers are still listed by gatekeeper
	// if not, disconnect
	auto pit = peers->begin();
	std::shared_ptr<CPeer>peer = nullptr;
	while ( nullptr != (peer = peers->FindNextPeer(EProtocol::bm, pit)) )
	{
		if ( nullptr == ilmap->FindMapItem(peer->GetCallsign().GetBase()) )
		{
			// send disconnect packet
			EncodeDisconnectPacket(&buffer);
			Send(buffer, peer->GetIp());
			std::cout << "Sending disconnect packet to BM peer " << peer->GetCallsign() << std::endl;
			// remove client
			peers->RemovePeer(peer);
		}
	}

	// check if all ours peers listed by gatekeeper are connected
	// if not, connect or reconnect
	for ( auto it=ilmap->begin(); it!=ilmap->end(); it++ )
	{
		const auto cs = it->first;
		if (0 == cs.substr(0, 2).compare("BM") && (nullptr==peers->FindPeer(CCallsign(cs), EProtocol::bm)))
		{
			// send connect packet to re-initiate peer link
			EncodeConnectPacket(&buffer, it->second.GetModules().c_str());
			Send(buffer, it->second.GetIp(), m_Port);
			std::cout << "Sending connect packet to BM peer " << cs << " @ " << it->second.GetIp() << " for modules " << it->second.GetModules() << std::endl;
		}
	}

	// done
	g_Reflector.ReleasePeers();
	g_GateKeeper.ReleaseInterlinkMap();
}


////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CBMProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
{
	CCallsign peer;

	// todo: verify Packet.GetModuleId() is in authorized list of XLX of origin
	// todo: do the same for DVFrame and DVLAstFrame packets

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
		CCallsign my(Header->GetMyCallsign());
		CCallsign rpt1(Header->GetRpt1Callsign());
		CCallsign rpt2(Header->GetRpt2Callsign());
		// no stream open yet, open a new one
		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::bm, Header->GetRpt2Module());
		if ( client )
		{
			// and try to open the stream
			if ( (stream = g_Reflector.OpenStream(Header, client)) != nullptr )
			{
				// keep the handle
				m_Streams[stream->GetStreamId()] = stream;
			}
			// get origin
			peer = client->GetCallsign();
		}
		// release
		g_Reflector.ReleaseClients();
		// update last heard
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, peer, EProtocol::bm);
		g_Reflector.ReleaseUsers();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CBMProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
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

bool CBMProtocol::IsValidKeepAlivePacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if (Buffer.size() == 9)
	{
		callsign->SetCallsign(Buffer.data(), 8);
		valid = callsign->IsValid();
	}
	return valid;
}


bool CBMProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign, char *modules, CVersion *version)
{
	bool valid = false;
	if ((Buffer.size() == 39) && (Buffer.data()[0] == 'L') && (Buffer.data()[38] == 0))
	{
		callsign->SetCallsign((const uint8_t *)&(Buffer.data()[1]), 8);
		::strcpy(modules, (const char *)&(Buffer.data()[12]));
		valid = callsign->IsValid();
		*version = CVersion(Buffer.data()[9], Buffer.data()[10], Buffer.data()[11]);
		for ( unsigned i = 0; i < ::strlen(modules); i++ )
		{
			valid &= IsLetter(modules[i]);
		}
	}
	return valid;
}

bool CBMProtocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if ((Buffer.size() == 10) && (Buffer.data()[0] == 'U') && (Buffer.data()[9] == 0))
	{
		callsign->SetCallsign((const uint8_t *)&(Buffer.data()[1]), 8);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CBMProtocol::IsValidAckPacket(const CBuffer &Buffer, CCallsign *callsign, char *modules, CVersion *version)
{
	bool valid = false;
	if ((Buffer.size() == 39) && (Buffer.data()[0] == 'A') && (Buffer.data()[38] == 0))
	{
		callsign->SetCallsign((const uint8_t *)&(Buffer.data()[1]), 8);
		::strcpy(modules, (const char *)&(Buffer.data()[12]));
		valid = callsign->IsValid();
		*version = CVersion(Buffer.data()[9], Buffer.data()[10], Buffer.data()[11]);
		for ( unsigned i = 0; i < ::strlen(modules); i++ )
		{
			valid &= IsLetter(modules[i]);
		}
	}
	return valid;
}

bool CBMProtocol::IsValidNackPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	if ((Buffer.size() == 10) && (Buffer.data()[0] == 'N') && (Buffer.data()[9] == 0))
	{
		callsign->SetCallsign((const uint8_t *)&(Buffer.data()[1]), 8);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CBMProtocol::IsValidDvFramePacket(const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &dvframe)
{
	if ( 45==Buffer.size() && 0==Buffer.Compare((uint8_t *)"DSVT", 4) && 0x20U==Buffer.data()[4] && 0x20U==Buffer.data()[8] )
	{
		// create packet
		dvframe = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(
			// sid
			*((uint16_t *)&(Buffer.data()[12])),
			// dstar
			Buffer.data()[14], &(Buffer.data()[15]), &(Buffer.data()[24]),
			// dmr
			Buffer.data()[27], Buffer.data()[28], &(Buffer.data()[29]), &(Buffer.data()[38]),
			ECodecType::dmr, 0x40U==(Buffer.data()[14] & 0x40U)));

		// check validity of packet
		if ( dvframe && dvframe->IsValid() )
			return true;
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

void CBMProtocol::EncodeKeepAlivePacket(CBuffer *Buffer)
{
	Buffer->Set(GetReflectorCallsign());
}

void CBMProtocol::EncodeConnectPacket(CBuffer *Buffer, const char *Modules)
{
	uint8_t tag[] = { 'L' };

	// tag
	Buffer->Set(tag, sizeof(tag));
	// our callsign
	Buffer->resize(Buffer->size()+8);
	m_ReflectorCallsign.GetCallsign(Buffer->data()+1);
	// our version, fake it
	Buffer->Append((uint8_t)2);
	Buffer->Append((uint8_t)4);
	Buffer->Append((uint8_t)31);
	// the modules we share
	Buffer->Append(Modules);
	Buffer->resize(39);
}

void CBMProtocol::EncodeDisconnectPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 'U' };

	// tag
	Buffer->Set(tag, sizeof(tag));
	// our callsign
	Buffer->resize(Buffer->size()+8);
	m_ReflectorCallsign.GetCallsign(Buffer->data()+1);
	Buffer->Append((uint8_t)0);
}

void CBMProtocol::EncodeConnectAckPacket(CBuffer *Buffer, const char *Modules)
{
	uint8_t tag[] = { 'A' };

	// tag
	Buffer->Set(tag, sizeof(tag));
	// our callsign
	Buffer->resize(Buffer->size()+8);
	m_ReflectorCallsign.GetCallsign(Buffer->data()+1);
	// our version, fake it
	Buffer->Append((uint8_t)2);
	Buffer->Append((uint8_t)4);
	Buffer->Append((uint8_t)31);
	// the modules we share
	Buffer->Append(Modules);
	Buffer->resize(39);
}

void CBMProtocol::EncodeConnectNackPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 'N' };

	// tag
	Buffer->Set(tag, sizeof(tag));
	// our callsign
	Buffer->resize(Buffer->size()+8);
	m_ReflectorCallsign.GetCallsign(Buffer->data()+1);
	Buffer->Append((uint8_t)0);
}

bool CBMProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Packet, CBuffer &Buffer) const
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

bool CBMProtocol::EncodeDvFramePacket(const CDvFramePacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[] = { 'D','S','V','T',0x20,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };

	Buffer.Set(tag, sizeof(tag));
	Buffer.Append(Packet.GetStreamId());
	auto pid = (uint8_t)(Packet.GetPacketId() % 21u);
	if (Packet.IsLastPacket())
		pid |= 0x40u;
	Buffer.Append(pid);
	Buffer.Append((uint8_t *)Packet.GetCodecData(ECodecType::dstar), 9);
	Buffer.Append((uint8_t *)Packet.GetDvData(), 3);

	Buffer.Append((uint8_t)Packet.GetDmrPacketId());
	Buffer.Append((uint8_t)Packet.GetDmrPacketSubid());
	Buffer.Append((uint8_t *)Packet.GetCodecData(ECodecType::dmr), 9);
	Buffer.Append((uint8_t *)Packet.GetDvSync(), 7);

	return true;

}
