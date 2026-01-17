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

#include <cstring>

#include "URFPeer.h"
#include "URFProtocol.h"
#include "Reflector.h"
#include "GateKeeper.h"
#include "Global.h"

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CURFProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
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

void CURFProtocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	char      Modules[27];
	CVersion  Version;
	std::unique_ptr<CDvHeaderPacket> Header;
	std::unique_ptr<CDvFramePacket>  Frame;
	std::unique_ptr<CDvFramePacket>  LastFrame;

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
		else if ( IsValidKeepAlivePacket(Buffer, &Callsign) )
		{
			// find peer
			CPeers *peers = g_Reflector.GetPeers();
			std::shared_ptr<CPeer>peer = peers->FindPeer(Ip, EProtocol::urf);
			if ( peer != nullptr )
			{
				// keep it alive
				peer->Alive();
			}
			g_Reflector.ReleasePeers();
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
			std::cout << "URF (" << Version.GetMajor() << "." << Version.GetMinor() << "." << Version.GetRevision() << ") connect packet for modules " << Modules << " from " << Callsign <<  " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::urf, Modules) )
			{
				// acknowledge connecting request
				// following is version dependent
				if (EProtoRev::original == CURFPeer::GetProtocolRevision(Version))
				{
					// acknowledge the request
					EncodeConnectAckPacket(&Buffer, Modules);
					Send(Buffer, Ip);
				}
				else
				{
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
		else if ( IsValidAckPacket(Buffer, &Callsign, Modules, &Version)  )
		{
			std::cout << "URF ack packet for modules " << Modules << " from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::urf, Modules) )
			{
				// already connected ?
				CPeers *peers = g_Reflector.GetPeers();
				if ( peers->FindPeer(Callsign, Ip, EProtocol::urf) == nullptr )
				{
					// create the new peer
					// this also create one client per module
					std::shared_ptr<CPeer>peer = std::make_shared<CURFPeer>(Callsign, Ip, Modules, Version);

					// append the peer to reflector peer list
					// this also add all new clients to reflector client list
					peers->AddPeer(peer);
				}
				g_Reflector.ReleasePeers();
			}
		}
		else if ( IsValidDisconnectPacket(Buffer, &Callsign) )
		{
			std::cout << "URF disconnect packet from " << Callsign << " at " << Ip << std::endl;

			// find peer
			CPeers *peers = g_Reflector.GetPeers();
			std::shared_ptr<CPeer>peer = peers->FindPeer(Ip, EProtocol::urf);
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
			std::cout << "URF nack packet from " << Callsign << " at " << Ip << std::endl;
		}
		else
		{
			std::string title("Unknown URF packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep alive
	if ( m_LastKeepaliveTime.time() > URF_KEEPALIVE_PERIOD )
	{
		// handle keep alives
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}

	// peer connections
	if ( m_LastPeersLinkTime.time() > URF_RECONNECT_PERIOD )
	{
		// handle remote peers connections
		HandlePeerLinks();

		// update time
		m_LastPeersLinkTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CURFProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// check if origin of packet is local
		// if not, do not stream it out as it will cause
		// network loop between linked URF peers
		if ( packet->IsLocalOrigin() )
		{
			// encode it
			CBuffer buffer;
			if ( EncodeDvPacket(*packet, buffer) )
			{
				// and push it to all our clients linked to the module and who are not streaming in
				CClients *clients = g_Reflector.GetClients();
				auto it = clients->begin();
				std::shared_ptr<CClient>client = nullptr;
				while ( (client = clients->FindNextClient(EProtocol::urf, it)) != nullptr )
				{
					// is this client busy ?
					if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetPacketModule()) )
					{
						// no, send the packet
						// this is protocol revision dependent
						if (EProtoRev::original == client->GetProtocolRevision())
						{
							Send(buffer, client->GetIp());
						}
					}
				}
				g_Reflector.ReleaseClients();
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CURFProtocol::HandleKeepalives(void)
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
	while ( (peer = peers->FindNextPeer(EProtocol::urf, pit)) != nullptr )
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
			std::cout << "URF peer " << peer->GetCallsign() << " keepalive timeout" << std::endl;
			peers->RemovePeer(peer);
		}
	}
	g_Reflector.ReleasePeers();
}

////////////////////////////////////////////////////////////////////////////////////////
// Peers helpers

void CURFProtocol::HandlePeerLinks(void)
{
	CBuffer buffer;

	// get the list of peers
	auto ilmap = g_GateKeeper.GetInterlinkMap();
	CPeers *peers = g_Reflector.GetPeers();

	// check if all our connected peers are still listed by gatekeeper
	// if not, disconnect
	auto pit = peers->begin();
	std::shared_ptr<CPeer>peer = nullptr;
	while (nullptr != (peer = peers->FindNextPeer(EProtocol::urf, pit)))
	{
		if (nullptr == ilmap->FindMapItem(peer->GetCallsign().GetBase()))
		{
			// send disconnect packet
			EncodeDisconnectPacket(&buffer);
			Send(buffer, peer->GetIp());
			std::cout << "Sending disconnect packet to URF peer " << peer->GetCallsign() << std::endl;
			// remove client
			peers->RemovePeer(peer);
		}
	}

	// check if all ours peers listed by interlink file are connected
	// if not, connect or reconnect
	for ( auto it=ilmap->begin(); it!=ilmap->end(); it++ )
	{
		const auto cs = it->first;
		CCallsign callsign;
		callsign.SetCallsign(cs, false);
		if ((0 == cs.substr(0, 3).compare("URF")) && (nullptr==peers->FindPeer(callsign, EProtocol::urf)))
		{
#ifndef NO_DHT
			it->second.UpdateIP(g_Configure.GetString(g_Keys.ip.ipv6address).empty());
			if (it->second.GetIp().IsSet())
			{
				bool ok = true;
				// does everything match up?
				for (const auto c : it->second.GetModules())
				{
					if (std::string::npos == g_Configure.GetString(g_Keys.modules.modules).find(c))
					{	// is the local module not config'ed?
						ok = false;
						std::cerr << "This reflector has no module '" << c << "', so it can't interlink with " << it->first << std::endl;
					}
					else if (it->second.UsesDHT())
					{
						if (std::string::npos == it->second.GetCMods().find(c))
						{	// the remote module not config'ed!
							ok = false;
							std::cerr << it->first << " has no module '" << c << "'" << std::endl;
						}
						else if ((std::string::npos == it->second.GetTCMods().find(c)) != (std::string::npos == g_Configure.GetString(g_Keys.tc.modules).find(c)))
						{	// are the transcoding states on both sides mismatched?
							ok = false;
							std::cerr << "The transcode states for module '" << c << "' don't match for this reflector and " << it->first << std::endl;
						}
					}
				}
				if (ok)
				{

#endif
					// send connect packet to re-initiate peer link
					EncodeConnectPacket(&buffer, it->second.GetModules().c_str());
					Send(buffer, it->second.GetIp());
					std::cout << "Sent connect packet to URF peer " << cs << " @ " << it->second.GetIp() << " for modules " << it->second.GetModules() << std::endl;
#ifndef NO_DHT
				}
			}
			else // m_Ip is not set!
			{
				g_Reflector.GetDHTConfig(it->first);
			}
#endif
		}
	}

	// done
	g_Reflector.ReleasePeers();
	g_GateKeeper.ReleaseInterlinkMap();
}


////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CURFProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
{
	CCallsign peer;

	// todo: verify Packet.GetModuleId() is in authorized list of URF of origin
	// todo: do the same for DVFrame and DVLAstFrame packets

	// tag packet as remote peer origin
	Header->SetRemotePeerOrigin();

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
        
        // Critical Fix: Sanitize source callsign to strip suffixes (e.g. "KF8S D" -> "KF8S")
        my.SetCallsign(my.GetBase(), false);

		CCallsign rpt1(Header->GetRpt1Callsign());
		CCallsign rpt2(Header->GetRpt2Callsign());
		// no stream open yet, open a new one
		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::urf, Header->GetRpt2Module());
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
        CCallsign xlx = rpt2;
        xlx.SetCSModule(Header->GetRpt2Module());
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, xlx, EProtocol::urf);
		g_Reflector.ReleaseUsers();
	}
}

void CURFProtocol::OnDvFramePacketIn(std::unique_ptr<CDvFramePacket> &DvFrame, const CIp *Ip)
{
	// tag packet as remote peer origin
	DvFrame->SetRemotePeerOrigin();

	// and call base class
	CProtocol::OnDvFramePacketIn(DvFrame, Ip);
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CURFProtocol::IsValidKeepAlivePacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	uint8_t magic[] = { 'P','I','N','G' };
	if ((10 == Buffer.size()) && (0 == Buffer.Compare(magic, 4)))
	{
		callsign->CodeIn(Buffer.data()+4);
		valid = callsign->IsValid();
	}
	return valid;
}


bool CURFProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign, char *modules, CVersion *version)
{
	bool valid = false;
	uint8_t magic[] = { 'C','O','N','N' };
	if ((Buffer.size() == 40) && (0 == Buffer.Compare(magic, 4)) && (Buffer.data()[36] == 0))
	{
		callsign->CodeIn(Buffer.data()+4);
		valid = callsign->IsValid();
		*version = CVersion(Buffer.at(37), Buffer.at(38), Buffer.at(39));
		if (valid)
		{
			memcpy(modules, Buffer.data()+10, 27);
			for ( unsigned i = 0; i < strlen(modules); i++ )
			{
				auto moduleok = g_Reflector.IsValidModule(modules[i]);
				if (! moduleok)
				{
					valid = false;
					std::cout << "Requested module '" << modules[i] << "' is not confgured\n";
				}
			}
		}
	}
	return valid;
}

bool CURFProtocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	uint8_t magic[] = { 'D','I','S','C' };
	if ((Buffer.size() == 10) && (0 == Buffer.Compare(magic, 4)))
	{
		callsign->CodeIn(Buffer.data()+4);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CURFProtocol::IsValidAckPacket(const CBuffer &Buffer, CCallsign *callsign, char *modules, CVersion *version)
{
	bool valid = false;
	uint8_t magic[] = { 'A','C','K','N' };
	if ((Buffer.size() == 40) && (0 == Buffer.Compare(magic, 4)) && (Buffer.data()[36] == 0))
	{
		callsign->CodeIn(Buffer.data()+4);
		valid = callsign->IsValid();
		*version = CVersion(Buffer.at(37), Buffer.at(38), Buffer.at(39));
		memcpy(modules, Buffer.data()+10, 27);
		for ( unsigned i = 0; i < strlen(modules); i++ )
		{
			valid = valid && (g_Reflector.IsValidModule(modules[i]));
		}
	}
	return valid;
}

bool CURFProtocol::IsValidNackPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	bool valid = false;
	uint8_t magic[] = { 'N','A','C','K' };
	if ((Buffer.size() == 10) && (0 == Buffer.Compare(magic, 4)))
	{
		callsign->CodeIn(Buffer.data()+4);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CURFProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	uint8_t magic[] = { 'U', 'R', 'F', 'H' };
	if (Buffer.size()==CDvHeaderPacket::GetNetworkSize() && 0==Buffer.Compare(magic, 4))
	{
		header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(Buffer));
		if (header)
		{
			if (header->IsValid())
				return true;
			else
				header.reset();
		}
	}
	return false;
}

bool CURFProtocol::IsValidDvFramePacket(const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &dvframe)
{
	uint8_t magic[] = { 'U', 'R', 'F', 'F' };
	if (Buffer.size()==CDvFramePacket::GetNetworkSize() && 0==Buffer.Compare(magic, 4))
	{
		dvframe = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(Buffer));
		if (dvframe)
		{
			if (dvframe->IsValid())
				return true;
			else
				dvframe.reset();
		}
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

bool CURFProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &packet, CBuffer &buffer) const
{
	packet.EncodeInterlinkPacket(buffer);
	return true;
}

bool CURFProtocol::EncodeDvFramePacket(const CDvFramePacket &packet, CBuffer &buffer) const
{
	packet.EncodeInterlinkPacket(buffer);
	return true;
}

void CURFProtocol::EncodeKeepAlivePacket(CBuffer *Buffer)
{
	Buffer->Set("PING");
	Buffer->resize(10);
	g_Reflector.GetCallsign().CodeOut(Buffer->data()+4);
}

void CURFProtocol::EncodeConnectPacket(CBuffer *Buffer, const char *Modules)
{
	// tag
	Buffer->Set("CONN");
	// our callsign
	Buffer->resize(37);
	g_Reflector.GetCallsign().CodeOut(Buffer->data()+4);
	// our version
	Buffer->ReplaceAt(10, (uint8_t *)Modules, strlen(Modules));
	Buffer->Append((uint8_t)g_Version.GetMajor());
	Buffer->Append((uint8_t)g_Version.GetMinor());
	Buffer->Append((uint8_t)g_Version.GetRevision());
}

void CURFProtocol::EncodeDisconnectPacket(CBuffer *Buffer)
{
	Buffer->Set("DISC");
	// our callsign
	Buffer->resize(10);
	g_Reflector.GetCallsign().CodeOut(Buffer->data()+4);
}

void CURFProtocol::EncodeConnectAckPacket(CBuffer *Buffer, const char *Modules)
{
	Buffer->Set("ACKN");
	// our callsign
	Buffer->resize(37);
	g_Reflector.GetCallsign().CodeOut(Buffer->data()+4);
	// the shared modules
	Buffer->ReplaceAt(10, (uint8_t *)Modules, strlen(Modules));
	// our version
	Buffer->Append((uint8_t)g_Version.GetMajor());
	Buffer->Append((uint8_t)g_Version.GetMinor());
	Buffer->Append((uint8_t)g_Version.GetRevision());
}

void CURFProtocol::EncodeConnectNackPacket(CBuffer *Buffer)
{
	Buffer->Set("NACK");
	Buffer->resize(10);
	g_Reflector.GetCallsign().CodeOut(Buffer->data()+4);
}
