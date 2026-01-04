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

#include <iostream>
#include <map>
#include <ctime>
#include <iomanip>
#include "Global.h"
#include "DMRMMDVMClient.h"
#include "DMRMMDVMProtocol.h"
#include "BPTC19696.h"
#include "RS129.h"
#include "Golay2087.h"
#include "QR1676.h"

////////////////////////////////////////////////////////////////////////////////////////
// define

#define CMD_NONE        0
#define CMD_LINK        1
#define CMD_UNLINK      2

////////////////////////////////////////////////////////////////////////////////////////
// constants

static uint8_t g_DmrSyncBSVoice[]    = { 0x07,0x55,0xFD,0x7D,0xF7,0x5F,0x70 };
static uint8_t g_DmrSyncBSData[]     = { 0x0D,0xFF,0x57,0xD7,0x5D,0xF5,0xD0 };
static uint8_t g_DmrSyncMSVoice[]    = { 0x07,0xF7,0xD5,0xDD,0x57,0xDF,0xD0 };
static uint8_t g_DmrSyncMSData[]     = { 0x0D,0x5D,0x7F,0x77,0xFD,0x75,0x70 };


////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CDmrmmdvmProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	m_DefaultId = g_Configure.GetUnsigned(g_Keys.mmdvm.defaultid);
	// base class
	if (! CProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	// update time
	m_LastKeepaliveTime.start();

	// random number generator
	time_t t;
	::srand((unsigned) time(&t));
	m_uiAuthSeed = (uint32_t)rand();

	// done
	return true;
}



////////////////////////////////////////////////////////////////////////////////////////
// task

void CDmrmmdvmProtocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	int       iRssi;
	uint8_t     Cmd;
	uint8_t     CallType;
	std::unique_ptr<CDvHeaderPacket>  Header;
	std::unique_ptr<CDvFramePacket>   LastFrame;
	std::array<std::unique_ptr<CDvFramePacket>, 3> Frames;

	// handle incoming packets
#if DMR_IPV6==true
#if DMR_IPV4==true
	if ( ReceiveDS(Buffer, Ip, 20) )
#else
	if ( Receive6(Buffer, Ip, 20) )
#endif
#else
	if ( Receive4(Buffer, Ip, 20) )
#endif
	{
		//Buffer.DebugDump(g_Reflector.m_DebugFile);
		// crack the packet
		if ( IsValidDvFramePacket(Ip, Buffer, Header, Frames) )
		{
			for ( int i = 0; i < 3; i++ )
			{
				OnDvFramePacketIn(Frames.at(i), &Ip);
			}
		}
		else if ( IsValidDvHeaderPacket(Buffer, Header, &Cmd, &CallType) )
		{
			// callsign muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::dmrmmdvm) )
			{
				// handle it
				OnDvHeaderPacketIn(Header, Ip, Cmd, CallType);
			}
		}
		else if ( IsValidDvLastFramePacket(Buffer, LastFrame) )
		{
			OnDvFramePacketIn(LastFrame, &Ip);
		}
		else if ( IsValidConnectPacket(Buffer, &Callsign, Ip) )
		{
			std::cout << "DMRmmdvm connect packet from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::dmrmmdvm) )
			{
				// acknowledge the request
				EncodeConnectAckPacket(&Buffer, Callsign, m_uiAuthSeed);
				Send(Buffer, Ip);
			}
			else
			{
				// deny the request
				EncodeNackPacket(&Buffer, Callsign);
				Send(Buffer, Ip);
			}

		}
		else if ( IsValidAuthenticationPacket(Buffer, &Callsign, Ip) )
		{
			std::cout << "DMRmmdvm authentication packet from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::dmrmmdvm) )
			{
				// acknowledge the request
				EncodeAckPacket(&Buffer, Callsign);
				Send(Buffer, Ip);

				// add client if needed
				CClients *clients = g_Reflector.GetClients();
				std::shared_ptr<CClient>client = clients->FindClient(Callsign, Ip, EProtocol::dmrmmdvm);
				// client already connected ?
				if ( client == nullptr )
				{
					std::cout << "DMRmmdvm login from " << Callsign << " at " << Ip << std::endl;

					// create the client and append
					std::shared_ptr<CDmrmmdvmClient> newClient = std::make_shared<CDmrmmdvmClient>(Callsign, Ip);
					
					// Configure Scanner
					newClient->m_Scanner.Configure(
						g_Configure.GetBoolean(g_Keys.dmr.single),
						g_Configure.GetUnsigned(g_Keys.dmr.timeout),
						g_Configure.GetUnsigned(g_Keys.dmr.hold)
					);
					
					clients->AddClient(newClient);
				}
				else
				{
					client->Alive();
				}
				// and done
				g_Reflector.ReleaseClients();
			}
			else
			{
				// deny the request
				EncodeNackPacket(&Buffer, Callsign);
				Send(Buffer, Ip);
			}

		}
		else if ( IsValidDisconnectPacket(Buffer, &Callsign) )
		{
			std::cout << "DMRmmdvm disconnect packet from " << Callsign << " at " << Ip << std::endl;

			// find client & remove it
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::dmrmmdvm);
			if ( client != nullptr )
			{
				clients->RemoveClient(client);
			}
			g_Reflector.ReleaseClients();
		}
		else if ( IsValidConfigPacket(Buffer, &Callsign, Ip) )
		{
			std::cout << "DMRmmdvm configuration packet from " << Callsign << " at " << Ip << std::endl;

			// acknowledge the request
			EncodeAckPacket(&Buffer, Callsign);
			Send(Buffer, Ip);
		}
		else if ( IsValidKeepAlivePacket(Buffer, &Callsign) )
		{
			//std::cout << "DMRmmdvm keepalive packet from " << Callsign << " at " << Ip << std::endl;

			// find all clients with that callsign & ip and keep them alive
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(Callsign, Ip, EProtocol::dmrmmdvm, it)) != nullptr )
			{
				// acknowledge
				EncodeKeepAlivePacket(&Buffer, client);
				Send(Buffer, Ip);

				// and mark as alive
				client->Alive();
			}
			g_Reflector.ReleaseClients();
		}
		else if ( IsValidRssiPacket(Buffer, &Callsign, &iRssi) )
		{
			// std::cout << "DMRmmdvm RSSI packet from " << Callsign << " at " << Ip << std::endl

			// ignore...
		}
		else if ( IsValidOptionPacket(Buffer, &Callsign, Ip) )
		{
			std::cout << "DMRmmdvm options packet from " << Callsign << " at " << Ip << std::endl;

			// acknowledge the request
			EncodeAckPacket(&Buffer, Callsign);
			Send(Buffer, Ip);
		}
		else if ( Buffer.size() != 55 )
		{
			std::string title("Unknown DMRMMDVM packet from ");
			title += Ip.GetAddress();
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();


	// keep client alive
	if ( m_LastKeepaliveTime.time() > DMRMMDVM_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}

}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CDmrmmdvmProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip, uint8_t cmd, uint8_t CallType)
{
	bool lastheard = false;

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
		// firstfind this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::dmrmmdvm);
		if ( client )
		{
			// Mini DMR / Flexible Mode Logic
			if (!g_Configure.GetBoolean(g_Keys.dmr.xlx))
			{
				std::shared_ptr<CDmrmmdvmClient> dmrClient = std::dynamic_pointer_cast<CDmrmmdvmClient>(client);
				if (dmrClient)
				{
					// Map Destination ID (TG) to Module (if applicable, but we mostly care about TG)
					// Actually, DmrDstIdToModule handles dynamic mapping now.
					// But we want to use the RAW TG for subscription?
					// DmrDstIdToModule uses the map to find 'A' from TG.
					// If we are in XlxMode=false, DmrDstIdToModule uses the map.
					// rpt2 checks GetCSModule().
					// We need to know the Talkgroup.
					// Helper: module 'A' -> TG X.
					// Header->GetRpt2Callsign() call has Module set by DmrDstIdToModule.
					
					char mod = rpt2.GetCSModule();
					uint32_t tg = ModuleToDmrDestId(mod);
					
					// Mini DMR: Explicit Disconnect (TG 4000 or specific unlink cmd)
					if (tg == 4000 || cmd == CMD_UNLINK)
					{
						std::cout << "DMRmmdvm client " << client->GetCallsign() << " Mini DMR Disconnect (TG 4000)" << std::endl;
						dmrClient->m_Scanner.ClearSubscriptions();
						client->SetReflectorModule(' '); // Clear module attachment
						g_Reflector.ReleaseClients();
						return; 
					}
					
					// Anti-Kerchunk / Hold Check
					// If this is a new transmission (Header), we check access.
					if (!dmrClient->m_Scanner.CheckAccess(tg)) {
						// Blocked by Scanner Hold or not subscribed?
						// Wait, strict logic: "Clients subscribe... traffic is routed".
						// If I PTT on a TG, should I auto-subscribe?
						// Plan says: "Subscribe: Thread-safe update... First PTT Logic".
						// So we SHOULD subscribe.
						// But if we subscribe, CheckAccess(tg) will return true (unless held by OTHER).
						// So we add subscription first.
						
						// Add Subscription (Dynamic)
						unsigned int timeout = g_Configure.GetUnsigned(g_Keys.dmr.timeout);
						// Slot? Usually assume Slot 2 or from Header? Header has slot info?
						// CDvHeaderPacket doesn't easily expose slot in args here, passed in?
						// Header->GetBitField? 
						// Actually buffer parsing did it.
						// We don't have slot easily available here except from previous context?
						// Buffer parsing sets 'header' and 'cmd'.
						// Mini DMR Mode: Scanner Check
						// We need to know which slot the user is transmitting on.
						// The packet doesn't explicitly tell us (it's embedded in obscure bits or implicit).
						// However, if the user is transmitting on TG X, they MUST be subscribed to TG X.
						// So we can look up the slot from the scanner!
						int slot = dmrClient->m_Scanner.GetSubscriptionSlot(tg);
						if (slot == 0) slot = 2; // Default to TS2 if not found (e.g. initial PTT)

						// Auto-subscribe if not subscribed? 
						// If slot was 0, it means not subscribed. We should probably auto-subscribe.
						// But which slot? Usually TS2 is safe default for Hotspots.
						if (slot == 2 && dmrClient->m_Scanner.GetSubscriptionSlot(tg) == 0) {
                             // PTT -> Dynamic Subscription (isStatic=false)
 							 dmrClient->m_Scanner.AddSubscription(tg, 2, timeout, false);
						}
						
						// Check Access on the specific slot
						if (!dmrClient->m_Scanner.CheckAccess(tg, slot)) {
							// Blocked (Held by another TG on this slot)
							g_Reflector.ReleaseClients();
							return;
						}

						// FIX: Ensure OpenStream sees the client attached to this module
						client->SetReflectorModule(rpt2.GetCSModule());
					} else {
                        // Access Granted (Already Subscribed) - Renew Timer if Dynamic
                        unsigned int timeout = g_Configure.GetUnsigned(g_Keys.dmr.timeout);
                        int slot = dmrClient->m_Scanner.GetSubscriptionSlot(tg);
                        if (slot != 0) {
                             dmrClient->m_Scanner.RenewSubscription(tg, slot, timeout);
                        }
                    }
                    
                    // Always ensure module is set if we are processing this packet (Access Granted)
                    // DEBUG: Trace Module Assignment
                    // std::cout << "DEBUG: " << client->GetCallsign().GetCS() << " assigned to module " << rpt2.GetCSModule() << std::endl;
                    client->SetReflectorModule(rpt2.GetCSModule());
				}
			}

			// process cmd if any
			if ( !client->HasReflectorModule() )
			{
				// not linked yet
				if ( cmd == CMD_LINK )
				{
					if ( g_Reflector.IsValidModule(rpt2.GetCSModule()) )
					{
						// In Mini DMR, we don't necessarily "Link" the client object,
						// but existing logic uses SetReflectorModule for routing.
						// WE should ONLY do this in XLX mode.
						if (g_Configure.GetBoolean(g_Keys.dmr.xlx)) {
							std::cout << "DMRmmdvm client " << client->GetCallsign() << " linking on module " << rpt2.GetCSModule() << std::endl;
							// link
							client->SetReflectorModule(rpt2.GetCSModule());
						}
					}
					else
					{
						std::cout << "DMRMMDVM node " << rpt1 << " link attempt on non-existing module" << std::endl;
					}
				}
			}
			else
			{
				// already linked
				if ( cmd == CMD_UNLINK )
				{
					std::cout << "DMRmmdvm client " << client->GetCallsign() << " unlinking" << std::endl;
					// unlink
					client->SetReflectorModule(' ');
				}
				else
				{
					// replace rpt2 module with currently linked module
					auto m = client->GetReflectorModule();
					Header->SetRpt2Module(m);
					rpt2.SetCSModule(m);
				}
			}

			// and now, re-check module is valid && that it's not a private call
			if ( g_Reflector.IsValidModule(rpt2.GetCSModule()) && (CallType == DMR_GROUP_CALL) )
			{
				// yes, try to open the stream
				if ( (stream = g_Reflector.OpenStream(Header, client)) != nullptr )
				{
					// keep the handle
					m_Streams[stream->GetStreamId()] = stream;
					lastheard = true;
				}
			}
		}
		else
		{
			lastheard = true;
		}

		// release
		g_Reflector.ReleaseClients();

		// update last heard
		if ( lastheard )
		{
			// Fix Dashboard Target Display
            // Construct target with explicit stringID to show "7002" instead of "CQCQCQ"
            // CRITICAL FIX: Header is unique_ptr and was MOVED in OpenStream above if stream opened.
            // We cannot access Header here if stream != nullptr.
            // Reconstruct a clean target object.
            CCallsign target("CQCQCQ"); // Default safe initialization
            
            // uiDstId is not in scope, recover it from the module (which relies on urfd.ini mapping)
            uint32_t tg = ModuleToDmrDestId(rpt2.GetCSModule());
            target.SetCallsign(std::to_string(tg));
            
			g_Reflector.GetUsers()->Hearing(my, target, rpt1, rpt2, EProtocol::dmrmmdvm);
			g_Reflector.ReleaseUsers();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CDmrmmdvmProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// get our sender's id
		const auto mod = packet->GetPacketModule();

		// encode buffers for both slots
		CBuffer bufferTS1;
		CBuffer bufferTS2;

		// check if it's header
		if ( packet->IsDvHeader() )
		{
			// update local stream cache
			// this relies on queue feeder setting valid module id
			m_StreamsCache[mod].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet.get());
			m_StreamsCache[mod].m_uiSeqId = 0;

            // Calculate Destination ID based on Module (XLX or Mini DMR logic)
            uint32_t tg = ModuleToDmrDestId(packet->GetPacketModule());

			// encode it
			EncodeMMDVMHeaderPacket((CDvHeaderPacket &)*packet.get(), m_StreamsCache[mod].m_uiSeqId, tg, 1, &bufferTS1);
			EncodeMMDVMHeaderPacket((CDvHeaderPacket &)*packet.get(), m_StreamsCache[mod].m_uiSeqId, tg, 2, &bufferTS2);
			m_StreamsCache[mod].m_uiSeqId = 1;

            // Store TG in cache for subsequent frames? Or recalculate?
            // ModuleToDmrDestId is fast enough.
		}
		// check if it's a last frame
		else if ( packet->IsLastPacket() )
		{
            uint32_t tg = ModuleToDmrDestId(packet->GetPacketModule());

			// encode it
			EncodeLastMMDVMPacket(m_StreamsCache[mod].m_dvHeader, m_StreamsCache[mod].m_uiSeqId, tg, 1, &bufferTS1);
			EncodeLastMMDVMPacket(m_StreamsCache[mod].m_dvHeader, m_StreamsCache[mod].m_uiSeqId, tg, 2, &bufferTS2);
			m_StreamsCache[mod].m_uiSeqId = (m_StreamsCache[mod].m_uiSeqId + 1) & 0xFF;
		}
		// otherwise, just a regular DV frame
		else
		{
            uint32_t tg = ModuleToDmrDestId(packet->GetPacketModule());

			// update local stream cache or send triplet when needed
			switch ( packet->GetDmrPacketSubid() )
			{
			case 1:
				m_StreamsCache[mod].m_dvFrame0 = CDvFramePacket((const CDvFramePacket &)*packet.get());
				break;
			case 2:
				m_StreamsCache[mod].m_dvFrame1 = CDvFramePacket((const CDvFramePacket &)*packet.get());
				break;
			case 3:
				EncodeMMDVMPacket(m_StreamsCache[mod].m_dvHeader, m_StreamsCache[mod].m_dvFrame0, m_StreamsCache[mod].m_dvFrame1, (const CDvFramePacket &)*packet.get(), m_StreamsCache[mod].m_uiSeqId, tg, 1, &bufferTS1);
				EncodeMMDVMPacket(m_StreamsCache[mod].m_dvHeader, m_StreamsCache[mod].m_dvFrame0, m_StreamsCache[mod].m_dvFrame1, (const CDvFramePacket &)*packet.get(), m_StreamsCache[mod].m_uiSeqId, tg, 2, &bufferTS2);
				m_StreamsCache[mod].m_uiSeqId = (m_StreamsCache[mod].m_uiSeqId + 1) & 0xFF;
				break;
			default:
				break;
			}
		}

		// send it
		if ( bufferTS1.size() > 0 || bufferTS2.size() > 0 )
		{
			// and push it to all our clients linked to the module and who are not streaming in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
            
            // Calculate TG again for convenience or use from above scope?
            // The logic above is inside if/else blocks.
            // Recalculate is safest and clean.
            uint32_t tg = ModuleToDmrDestId(packet->GetPacketModule());

			while ( (client = clients->FindNextClient(EProtocol::dmrmmdvm, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() )
				{
					if (g_Configure.GetBoolean(g_Keys.dmr.xlx))
					{
						// Legacy XLX Mode: Link Check
						// Default to TS2 buffer for XLX
						// Or should we support both slots in XLX? Usually Reflector runs on TS2.
						if (client->GetReflectorModule() == packet->GetPacketModule())
							Send(bufferTS2, client->GetIp()); 
					}
					else
					{
						// Mini DMR Mode: Scanner Check
						std::shared_ptr<CDmrmmdvmClient> dmrClient = std::dynamic_pointer_cast<CDmrmmdvmClient>(client);
						if (dmrClient)
						{
							// uint32_t tg = ModuleToDmrDestId(packet->GetPacketModule()); // Already calculated
							
							// Check Access for each slot independently
                            bool ts1 = bufferTS1.size() > 0 && dmrClient->m_Scanner.CheckAccess(tg, 1);
                            bool ts2 = bufferTS2.size() > 0 && dmrClient->m_Scanner.CheckAccess(tg, 2);

							if (ts1) {
                                Send(bufferTS1, client->GetIp());
                            }
								
							if (ts2) {
                                Send(bufferTS2, client->GetIp());
                            }
						}
					}
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CDmrmmdvmProtocol::HandleKeepalives(void)
{
	// DMRhomebrew protocol keepalive request is client tasks
	// here, just check that all clients are still alive
	// and disconnect them if not

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::dmrmmdvm, it)) != nullptr )
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
			// no, disconnect
			CBuffer disconnect;
			Send(disconnect, client->GetIp());

			// remove it
			std::cout << "DMRmmdvm client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}

	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CDmrmmdvmProtocol::IsValidKeepAlivePacket(const CBuffer &Buffer, CCallsign *callsign)
{
	uint8_t tag[] = { 'R','P','T','P','I','N','G' };

	bool valid = false;
	if ( (Buffer.size() == 11) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[10],Buffer.data()[9]),MAKEWORD(Buffer.data()[8],Buffer.data()[7]));
		callsign->SetDmrid(uiRptrId, true);
		callsign->SetCSModule(MMDVM_MODULE_ID);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign, const CIp &Ip)
{
	uint8_t tag[] = { 'R','P','T','L' };

	bool valid = false;
	if ( (Buffer.size() == 8) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],Buffer.data()[4]));
		callsign->SetDmrid(uiRptrId, true);
		callsign->SetCSModule(MMDVM_MODULE_ID);
		valid = callsign->IsValid();
		if ( !valid)
		{
			std::cout << "Invalid callsign in DMRmmdvm RPTL packet from IP: " << Ip << " CS:" << *callsign << " DMRID:" << callsign->GetDmrid() << std::endl;
		}
	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidAuthenticationPacket(const CBuffer &Buffer, CCallsign *callsign, const CIp &Ip)
{
	uint8_t tag[] = { 'R','P','T','K' };

	bool valid = false;
	if ( (Buffer.size() == 40) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],Buffer.data()[4]));
		callsign->SetDmrid(uiRptrId, true);
		callsign->SetCSModule(MMDVM_MODULE_ID);
		valid = callsign->IsValid();
		if ( !valid)
		{
			std::cout << "Invalid callsign in DMRmmdvm RPTK packet from IP: " << Ip << " CS:" << *callsign << " DMRID:" << callsign->GetDmrid() << std::endl;
		}

	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	uint8_t tag[] = { 'R','P','T','C','L' };

	bool valid = false;
	if ( (Buffer.size() == 13) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],Buffer.data()[4]));
		callsign->SetDmrid(uiRptrId, true);
		callsign->SetCSModule(MMDVM_MODULE_ID);
		valid = callsign->IsValid();
	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidConfigPacket(const CBuffer &Buffer, CCallsign *callsign, const CIp &Ip)
{
	uint8_t tag[] = { 'R','P','T','C' };

	bool valid = false;
	if ( (Buffer.size() == 302) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],Buffer.data()[4]));
		callsign->SetDmrid(uiRptrId, true);
		callsign->SetCSModule(MMDVM_MODULE_ID);
		valid = callsign->IsValid();
		if ( !valid)
		{
			std::cout << "Invalid callsign in DMRmmdvm RPTC packet from IP: " << Ip << " CS:" << *callsign << " DMRID:" << callsign->GetDmrid() << std::endl;
		}
		else
		{
			// Update Options from Description
			// Description starts at offset 67, length 40 (approx). Buffer size 302.
			if (Buffer.size() >= 107) {
				std::string desc((const char*)(Buffer.data() + 67), 40);
				// Trim nulls or grab until null
				size_t nullpos = desc.find('\0');
				if (nullpos != std::string::npos) desc.resize(nullpos);
				
				// Find client
				CClients *clients = g_Reflector.GetClients();
				std::shared_ptr<CClient> client = clients->FindClient(*callsign, Ip, EProtocol::dmrmmdvm);
				if (client) {
					std::shared_ptr<CDmrmmdvmClient> dmrClient = std::dynamic_pointer_cast<CDmrmmdvmClient>(client);
					if (dmrClient) {
						std::cout << "DMRmmdvm Options Update for " << client->GetCallsign() << ": " << desc << std::endl;
					dmrClient->m_Scanner.UpdateSubscriptions(desc);
					// FIX: Update Visual Module based on First Subscription
					uint32_t firstTG = dmrClient->m_Scanner.GetFirstSubscription();
					if (firstTG > 0) {
						char mod = DmrDstIdToModule(firstTG);
						if (mod != ' ') dmrClient->SetReflectorModule(mod);
					}
				}
			}
			g_Reflector.ReleaseClients();
			}
		}

	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidOptionPacket(const CBuffer &Buffer, CCallsign *callsign, const CIp &Ip)
{
	uint8_t tag[] = { 'R','P','T','O' };

	bool valid = false;
	if ( (Buffer.size() >= 8) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],Buffer.data()[4]));
		callsign->SetDmrid(uiRptrId, true);
		callsign->SetCSModule(MMDVM_MODULE_ID);
		valid = callsign->IsValid();

		if (valid && Buffer.size() > 8) {
			// Extract Options String
			std::string options((const char*)(Buffer.data() + 8), Buffer.size() - 8);
			// Trim potential nulls
			size_t nullpos = options.find('\0');
			if (nullpos != std::string::npos) options.resize(nullpos);

			// Find client and update
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient> client = clients->FindClient(*callsign, Ip, EProtocol::dmrmmdvm);
			if (client) {
				std::shared_ptr<CDmrmmdvmClient> dmrClient = std::dynamic_pointer_cast<CDmrmmdvmClient>(client);
				if (dmrClient) {
					std::cout << "DMRmmdvm RPTO Options for " << client->GetCallsign() << ": " << options << std::endl;
					dmrClient->m_Scanner.UpdateSubscriptions(options);
					// FIX: Update Visual Module based on First Subscription
					uint32_t firstTG = dmrClient->m_Scanner.GetFirstSubscription();
					if (firstTG > 0) {
						char mod = DmrDstIdToModule(firstTG);
						if (mod != ' ') dmrClient->SetReflectorModule(mod);
					}
				}
			}
			g_Reflector.ReleaseClients();
		}
	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidRssiPacket(const CBuffer &Buffer, CCallsign *callsign, int *rssi)
{
	uint8_t tag[] = { 'R','P','T','I','N','T','R' };

	bool valid = false;
	if ( (Buffer.size() == 17) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		// ignore rest of it, as not used
		// dmrid is asci hex on 8 bytes
		// rssi is ascii :x-xx
		valid = true;
	}
	return valid;
}

bool CDmrmmdvmProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header, uint8_t *cmd, uint8_t *CallType)
{
	uint8_t tag[] = { 'D','M','R','D' };

	*cmd = CMD_NONE;

	if ( (Buffer.size() == 55) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		// frame details
		uint8_t uiFrameType = (Buffer.data()[15] & 0x30) >> 4;
		uint8_t uiSlot = (Buffer.data()[15] & 0x80) ? DMR_SLOT2 : DMR_SLOT1;
		uint8_t uiCallType = (Buffer.data()[15] & 0x40) ? DMR_PRIVATE_CALL : DMR_GROUP_CALL;
		uint8_t uiSlotType = Buffer.data()[15] & 0x0F;
		//std::cout << (int)uiSlot << std::endl;
		if ( (uiFrameType == DMRMMDVM_FRAMETYPE_DATASYNC) &&
				(uiSlot == DMRMMDVM_REFLECTOR_SLOT) &&
				(uiSlotType == MMDVM_SLOTTYPE_HEADER) )
		{
			// extract sync
			uint8_t dmrsync[7];
			dmrsync[0] = Buffer.data()[33] & 0x0F;
			memcpy(&dmrsync[1], &Buffer.data()[34], 5);
			dmrsync[6] = Buffer.data()[39] & 0xF0;
			// and check
			if ( (memcmp(dmrsync, g_DmrSyncMSData, sizeof(dmrsync)) == 0) ||
					(memcmp(dmrsync, g_DmrSyncBSData, sizeof(dmrsync)) == 0))
			{
				// get payload
				//CBPTC19696 bptc;
				//uint8_t lcdata[12];
				//bptc.decode(&(Buffer.data()[20]), lcdata);

				// crack DMR header
				//uint8_t uiSeqId = Buffer.data()[4];
				uint32_t uiSrcId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],0));
				uint32_t uiDstId = MAKEDWORD(MAKEWORD(Buffer.data()[10],Buffer.data()[9]),MAKEWORD(Buffer.data()[8],0));
				uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[14],Buffer.data()[13]),MAKEWORD(Buffer.data()[12],Buffer.data()[11]));
				//uint8_t uiVoiceSeq = (Buffer.data()[15] & 0x0F);
				uint32_t uiStreamId = *(uint32_t *)(&Buffer.data()[16]);

				// call type
				*CallType = uiCallType;

				// link/unlink command ?
				if ( uiDstId == 4000 )
				{
					*cmd = CMD_UNLINK;
				}
				else if ( DmrDstIdToModule(uiDstId) != ' ' )
				{
					*cmd = CMD_LINK;
				}
				else
				{
					*cmd = CMD_NONE;
				}

				// build DVHeader
				CCallsign csMY = CCallsign("", uiSrcId);
				CCallsign rpt1 = CCallsign("", uiRptrId);
				rpt1.SetCSModule(MMDVM_MODULE_ID);
				CCallsign rpt2 = m_ReflectorCallsign;
				rpt2.SetCSModule(DmrDstIdToModule(uiDstId));

				// and packet
				header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(uiSrcId, CCallsign("CQCQCQ"), rpt1, rpt2, uiStreamId, 0, 0));
				if ( header && header->IsValid() )
					return true;
			}
		}
	}
	return false;
}

bool CDmrmmdvmProtocol::IsValidDvFramePacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header, std::array<std::unique_ptr<CDvFramePacket>, 3> &frames)
{
	uint8_t tag[] = { 'D','M','R','D' };

	if ( (Buffer.size() == 55) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		// frame details
		uint8_t uiFrameType = (Buffer.data()[15] & 0x30) >> 4;
		uint8_t uiSlot = (Buffer.data()[15] & 0x80) ? DMR_SLOT2 : DMR_SLOT1;
		uint8_t uiCallType = (Buffer.data()[15] & 0x40) ? DMR_PRIVATE_CALL : DMR_GROUP_CALL;
		if ( ((uiFrameType == DMRMMDVM_FRAMETYPE_VOICE) || (uiFrameType == DMRMMDVM_FRAMETYPE_VOICESYNC)) &&
				(uiSlot == DMRMMDVM_REFLECTOR_SLOT) && (uiCallType == DMR_GROUP_CALL) )
		{
			// crack DMR header
			//uint8_t uiSeqId = Buffer.data()[4];
			uint32_t uiSrcId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],0));
			uint32_t uiDstId = MAKEDWORD(MAKEWORD(Buffer.data()[10],Buffer.data()[9]),MAKEWORD(Buffer.data()[8],0));
			uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[14],Buffer.data()[13]),MAKEWORD(Buffer.data()[12],Buffer.data()[11]));
			uint8_t uiVoiceSeq = (Buffer.data()[15] & 0x0F);
			uint32_t uiStreamId = *(uint32_t *)(&Buffer.data()[16]);

			auto stream = GetStream(uiStreamId, &Ip);
			if ( !stream )
			{
				std::cout << std::showbase << std::hex;
				static std::map<uint32_t, std::time_t> last_late_entry;
				std::time_t now = std::time(nullptr);
				uint32_t sid = ntohl(uiStreamId);

				if (last_late_entry.find(sid) == last_late_entry.end() || (now - last_late_entry[sid]) > 60) {
					std::cout << "Late entry DMR voice frame, creating DMR header for DMR stream ID " << std::hex << std::showbase << sid 
							  << std::noshowbase << std::dec << " on " << Ip 
							  << " (Suppressed for 60s)" << std::endl;
					last_late_entry[sid] = now;
				}
				std::cout << std::noshowbase << std::dec;
				uint8_t cmd;

				// link/unlink command ?
				if ( uiDstId == 4000 )
				{
					cmd = CMD_UNLINK;
				}
				else if ( DmrDstIdToModule(uiDstId) != ' ' )
				{
					cmd = CMD_LINK;
				}
				else
				{
					cmd = CMD_NONE;
				}

				// build DVHeader
				CCallsign csMY = CCallsign("", uiSrcId);
				CCallsign rpt1 = CCallsign("", uiRptrId);
				rpt1.SetCSModule(MMDVM_MODULE_ID);
				CCallsign rpt2 = m_ReflectorCallsign;
				rpt2.SetCSModule(DmrDstIdToModule(uiDstId));

				// and packet
				header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(uiSrcId, CCallsign("CQCQCQ"), rpt1, rpt2, uiStreamId, 0, 0));

				if ( g_GateKeeper.MayTransmit(header->GetMyCallsign(), Ip, EProtocol::dmrmmdvm) )
				{
					// handle it
					OnDvHeaderPacketIn(header, Ip, cmd, uiCallType);
				}
			}

			// crack payload
			uint8_t dmrframe[33];
			uint8_t dmr3ambe[27];
			uint8_t dmrambe[9];
			uint8_t dmrsync[7];
			// get the 33 bytes ambe
			memcpy(dmrframe, &(Buffer.data()[20]), 33);
			// extract the 3 ambe frames
			memcpy(dmr3ambe, dmrframe, 14);
			dmr3ambe[13] &= 0xF0;
			dmr3ambe[13] |= (dmrframe[19] & 0x0F);
			memcpy(&dmr3ambe[14], &dmrframe[20], 13);
			// extract sync
			dmrsync[0] = dmrframe[13] & 0x0F;
			memcpy(&dmrsync[1], &dmrframe[14], 5);
			dmrsync[6] = dmrframe[19] & 0xF0;

			// debug
			//CBuffer dump;
			//dump.Set(dmrsync, 6);
			//dump.DebugDump(g_Reflector.m_DebugFile);

			// and create 3 dv frames
			// frame1
			memcpy(dmrambe, &dmr3ambe[0], 9);
			frames[0] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 1, false));

			// frame2
			memcpy(dmrambe, &dmr3ambe[9], 9);
			frames[1] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 2, false));

			// frame3
			memcpy(dmrambe, &dmr3ambe[18], 9);
			frames[2] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 3, false));

			// check
			if (frames[0] && frames[1] && frames[2])
				return true;
		}
	}
	return false;
}

bool CDmrmmdvmProtocol::IsValidDvLastFramePacket(const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &frame)
{
	uint8_t tag[] = { 'D','M','R','D' };

	if ( (Buffer.size() == 55) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		// frame details
		uint8_t uiFrameType = (Buffer.data()[15] & 0x30) >> 4;
		uint8_t uiSlot = (Buffer.data()[15] & 0x80) ? DMR_SLOT2 : DMR_SLOT1;
		//uint8_t uiCallType = (Buffer.data()[15] & 0x40) ? DMR_PRIVATE_CALL : DMR_GROUP_CALL;
		uint8_t uiSlotType = Buffer.data()[15] & 0x0F;
		//std::cout << (int)uiSlot << std::endl;
		if ( (uiFrameType == DMRMMDVM_FRAMETYPE_DATASYNC) &&
				(uiSlot == DMRMMDVM_REFLECTOR_SLOT) &&
				(uiSlotType == MMDVM_SLOTTYPE_TERMINATOR) )
		{
			// extract sync
			uint8_t dmrsync[7];
			dmrsync[0] = Buffer.data()[33] & 0x0F;
			memcpy(&dmrsync[1], &Buffer.data()[34], 5);
			dmrsync[6] = Buffer.data()[39] & 0xF0;
			// and check
			if ( (memcmp(dmrsync, g_DmrSyncMSData, sizeof(dmrsync)) == 0) ||
					(memcmp(dmrsync, g_DmrSyncBSData, sizeof(dmrsync)) == 0))
			{
				// get payload
				//CBPTC19696 bptc;
				//uint8_t lcdata[12];
				//bptc.decode(&(Buffer.data()[20]), lcdata);

				// crack DMR header
				//uint8_t uiSeqId = Buffer.data()[4];
				//uint32_t uiSrcId = MAKEDWORD(MAKEWORD(Buffer.data()[7],Buffer.data()[6]),MAKEWORD(Buffer.data()[5],0));
				//uint32_t uiDstId = MAKEDWORD(MAKEWORD(Buffer.data()[10],Buffer.data()[9]),MAKEWORD(Buffer.data()[8],0));
				//uint32_t uiRptrId = MAKEDWORD(MAKEWORD(Buffer.data()[14],Buffer.data()[13]),MAKEWORD(Buffer.data()[12],Buffer.data()[11]));
				//uint8_t uiVoiceSeq = (Buffer.data()[15] & 0x0F);
				uint32_t uiStreamId = *(uint32_t *)(&Buffer.data()[16]);

				// dummy ambe
				uint8_t ambe[9];
				memset(ambe, 0, sizeof(ambe));


				// and packet
				frame = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(ambe, dmrsync, uiStreamId, 0, 0, true));
				if (frame)
					return true;
			}
		}
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

void CDmrmmdvmProtocol::EncodeKeepAlivePacket(CBuffer *Buffer, std::shared_ptr<CClient>Client)
{
	uint8_t tag[] = { 'M','S','T','P','O','N','G' };

	Buffer->Set(tag, sizeof(tag));
	uint32_t uiDmrId = Client->GetCallsign().GetDmrid();
	Buffer->Append((uint8_t *)&uiDmrId, 4);
}

void CDmrmmdvmProtocol::EncodeAckPacket(CBuffer *Buffer, const CCallsign &Callsign)
{
	uint8_t tag[] = { 'R','P','T','A','C','K' };

	Buffer->Set(tag, sizeof(tag));
}

void CDmrmmdvmProtocol::EncodeConnectAckPacket(CBuffer *Buffer, const CCallsign &Callsign, uint32_t AuthSeed)
{
	uint8_t tag[] = { 'R','P','T','A','C','K' };

	Buffer->Set(tag, sizeof(tag));
	Buffer->Append(AuthSeed);
}

void CDmrmmdvmProtocol::EncodeNackPacket(CBuffer *Buffer, const CCallsign &Callsign)
{
	uint8_t tag[] = { 'M','S','T','N','A','K' };

	Buffer->Set(tag, sizeof(tag));
}

void CDmrmmdvmProtocol::EncodeClosePacket(CBuffer *Buffer, std::shared_ptr<CClient>Client)
{
	uint8_t tag[] = { 'M','S','T','C','L' };

	Buffer->Set(tag, sizeof(tag));
}


bool CDmrmmdvmProtocol::EncodeMMDVMHeaderPacket(const CDvHeaderPacket &Packet, uint8_t seqid, uint32_t dstId, uint8_t slot, CBuffer *Buffer) const
{
    // Debug Encode
    // std::cout << "DEBUG: EncodeHeader dstId=" << dstId << " Slot=" << (int)slot << std::endl;

	uint8_t tag[] = { 'D','M','R','D' };

	Buffer->Set(tag, sizeof(tag));

	// DMR header
	// uiSeqId
	Buffer->Append((uint8_t)seqid);
	// uiSrcId
	uint32_t uiSrcId = Packet.GetMyCallsign().GetDmrid();
    // Fallback to default ID if source has none (e.g. Analog bridge)
    if (uiSrcId == 0) uiSrcId = m_DefaultId;

	AppendDmrIdToBuffer(Buffer, uiSrcId);
	// uiDstId
	AppendDmrIdToBuffer(Buffer, dstId);
	// uiRptrId
	uint32_t uiRptrId = Packet.GetRpt1Callsign().GetDmrid();
	AppendDmrRptrIdToBuffer(Buffer, uiRptrId);
	// uiBitField
	uint8_t uiBitField =
		(DMRMMDVM_FRAMETYPE_DATASYNC << 4) |
		((slot == 2) ? 0x80 : 0x00) |
		MMDVM_SLOTTYPE_HEADER;
	Buffer->Append((uint8_t)uiBitField);
	// uiStreamId
	uint32_t uiStreamId = Packet.GetStreamId();
	Buffer->Append((uint32_t)uiStreamId);

	// Payload
	AppendVoiceLCToBuffer(Buffer, uiSrcId, dstId);

	// BER
	Buffer->Append((uint8_t)0);

	// RSSI
	Buffer->Append((uint8_t)0);

	// done
	return true;
}

void CDmrmmdvmProtocol::EncodeMMDVMPacket(const CDvHeaderPacket &Header, const CDvFramePacket &DvFrame0, const CDvFramePacket &DvFrame1, const CDvFramePacket &DvFrame2, uint8_t seqid, uint32_t dstId, uint8_t slot, CBuffer *Buffer) const
{
	uint8_t tag[] = { 'D','M','R','D' };
	Buffer->Set(tag, sizeof(tag));
	uint8_t cs[12];

	// DMR header
	// uiSeqId
	Buffer->Append((uint8_t)seqid);
	// uiSrcId
	uint32_t uiSrcId = Header.GetMyCallsign().GetDmrid();
	DvFrame0.GetMyCallsign().GetCallsign(cs);

    if(uiSrcId == 0){
		uiSrcId = DvFrame0.GetMyCallsign().GetDmrid();
	}
	if(uiSrcId == 0){
		uiSrcId = DvFrame1.GetMyCallsign().GetDmrid();
	}
	if(uiSrcId == 0){
		uiSrcId = DvFrame2.GetMyCallsign().GetDmrid();
	}
	if(uiSrcId == 0){
		uiSrcId = m_DefaultId;
	}

	AppendDmrIdToBuffer(Buffer, uiSrcId);
	// uiDstId
	AppendDmrIdToBuffer(Buffer, dstId);
	// uiRptrId
	uint32_t uiRptrId = Header.GetRpt1Callsign().GetDmrid();
	AppendDmrRptrIdToBuffer(Buffer, uiRptrId);
	// uiBitField
	uint8_t uiBitField =
		((slot == 2) ? 0x80 : 0x00);
	if ( DvFrame0.GetDmrPacketId() == 0 )
	{
		uiBitField |= (DMRMMDVM_FRAMETYPE_VOICESYNC << 4);
	}
	else
	{
		uiBitField |= (DMRMMDVM_FRAMETYPE_VOICE << 4);
	}
	uiBitField |= (DvFrame0.GetDmrPacketId() & 0x0F);
	Buffer->Append((uint8_t)uiBitField);

	// uiStreamId
	uint32_t uiStreamId = Header.GetStreamId();
	Buffer->Append((uint32_t)uiStreamId);

	// Payload
	// frame0
	Buffer->ReplaceAt(20, DvFrame0.GetCodecData(ECodecType::dmr), 9);
	// 1/2 frame1
	Buffer->ReplaceAt(29, DvFrame1.GetCodecData(ECodecType::dmr), 5);
	Buffer->ReplaceAt(33, (uint8_t)(Buffer->at(33) & 0xF0));
	// 1/2 frame1
	Buffer->ReplaceAt(39, DvFrame1.GetCodecData(ECodecType::dmr)+4, 5);
	Buffer->ReplaceAt(39, (uint8_t)(Buffer->at(39) & 0x0F));
	// frame2
	Buffer->ReplaceAt(44, DvFrame2.GetCodecData(ECodecType::dmr), 9);

	// sync or embedded signaling
	ReplaceEMBInBuffer(Buffer, DvFrame0.GetDmrPacketId());

	// debug
	//CBuffer dump;
	//dump.Set(&(Buffer->data()[33]), 7);
	//dump.DebugDump(g_Reflector.m_DebugFile);

	// BER
	Buffer->Append((uint8_t)0);

	// RSSI
	Buffer->Append((uint8_t)0);
}


void CDmrmmdvmProtocol::EncodeLastMMDVMPacket(const CDvHeaderPacket &Packet, uint8_t seqid, uint32_t dstId, uint8_t slot, CBuffer *Buffer) const
{
	uint8_t tag[] = { 'D','M','R','D' };

	Buffer->Set(tag, sizeof(tag));

	// DMR header
	// uiSeqId
	Buffer->Append((uint8_t)seqid);
	// uiSrcId
	uint32_t uiSrcId = Packet.GetMyCallsign().GetDmrid();
    // Fallback to default ID if source has none
    if (uiSrcId == 0) uiSrcId = m_DefaultId;

	AppendDmrIdToBuffer(Buffer, uiSrcId);
	// uiDstId
	AppendDmrIdToBuffer(Buffer, dstId);
	// uiRptrId
	uint32_t uiRptrId = Packet.GetRpt1Callsign().GetDmrid();
	AppendDmrRptrIdToBuffer(Buffer, uiRptrId);
	// uiBitField
	uint8_t uiBitField =
		(DMRMMDVM_FRAMETYPE_DATASYNC << 4) |
		((slot == 2) ? 0x80 : 0x00) |
		MMDVM_SLOTTYPE_TERMINATOR;
	Buffer->Append((uint8_t)uiBitField);
	// uiStreamId
	uint32_t uiStreamId = Packet.GetStreamId();
	Buffer->Append((uint32_t)uiStreamId);

	// Payload
	AppendTerminatorLCToBuffer(Buffer, uiSrcId, dstId);

	// BER
	Buffer->Append((uint8_t)0);

	// RSSI
	Buffer->Append((uint8_t)0);
}


////////////////////////////////////////////////////////////////////////////////////////
// DestId to Module helper

char CDmrmmdvmProtocol::DmrDstIdToModule(uint32_t tg) const
{
	if (g_Configure.GetBoolean(g_Keys.dmr.xlx))
	{
		// Legacy XLX Mode
		if (tg > 4000 && tg < 4027)
		{
			const char mod = 'A' + (tg - 4001U);
			if (g_Reflector.IsValidModule(mod))
			{
				return mod;
			}
		}
	}
	else
	{
		// Mini DMR Mode - Reverse Lookup
		// Iterate A-Z and check map
		for (char c = 'A'; c <= 'Z'; c++)
		{
			std::string key = g_Keys.dmr.map_prefix + c;
			if (g_Configure.Contains(key))
			{
				if (g_Configure.GetUnsigned(key) == tg)
					return c;
			}
			else
			{
				// Default Mapping check
				// If no map entry, assume default 4001-4026?
				// User said "allows custom mapping... default mapping A=4001... should be supported".
				// So if key missing, fallback to default?
				if (tg == (uint32_t)(4001 + (c - 'A')))
					return c;
			}
		}
	}
	return ' ';
}

uint32_t CDmrmmdvmProtocol::ModuleToDmrDestId(char m) const
{
	if (g_Configure.GetBoolean(g_Keys.dmr.xlx))
	{
		return (uint32_t)(m - 'A')+4001;
	}
	else
	{
		// Mini DMR Mode - Forward Lookup
		std::string key = g_Keys.dmr.map_prefix + m;
		if (g_Configure.Contains(key))
		{
			return g_Configure.GetUnsigned(key);
		}
		// Default fallback
		return (uint32_t)(m - 'A')+4001;
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// Buffer & LC helpers

void CDmrmmdvmProtocol::AppendVoiceLCToBuffer(CBuffer *buffer, uint32_t uiSrcId, uint32_t uiDstId) const
{
	uint8_t payload[33];

	// fill payload
	CBPTC19696 bptc;
	memset(payload, 0, sizeof(payload));
	// LC data
	uint8_t lc[12];
	{
		memset(lc, 0, sizeof(lc));
		// uiDstId
		lc[3] = (uint8_t)LOBYTE(HIWORD(uiDstId));
		lc[4] = (uint8_t)HIBYTE(LOWORD(uiDstId));
		lc[5] = (uint8_t)LOBYTE(LOWORD(uiDstId));
		// uiSrcId
		lc[6] = (uint8_t)LOBYTE(HIWORD(uiSrcId));
		lc[7] = (uint8_t)HIBYTE(LOWORD(uiSrcId));
		lc[8] = (uint8_t)LOBYTE(LOWORD(uiSrcId));
		// parity
		uint8_t parity[4];
		CRS129::encode(lc, 9, parity);
		lc[9]  = parity[2] ^ DMR_VOICE_LC_HEADER_CRC_MASK;
		lc[10] = parity[1] ^ DMR_VOICE_LC_HEADER_CRC_MASK;
		lc[11] = parity[0] ^ DMR_VOICE_LC_HEADER_CRC_MASK;
	}
	// sync
	memcpy(payload+13, g_DmrSyncBSData, sizeof(g_DmrSyncBSData));
	// slot type
	{
		// slot type
		uint8_t slottype[3];
		memset(slottype, 0, sizeof(slottype));
		slottype[0]  = (DMRMMDVM_REFLECTOR_COLOUR << 4) & 0xF0;
		slottype[0] |= (DMR_DT_VOICE_LC_HEADER  << 0) & 0x0FU;
		CGolay2087::encode(slottype);
		payload[12U] = (payload[12U] & 0xC0U) | ((slottype[0U] >> 2) & 0x3FU);
		payload[13U] = (payload[13U] & 0x0FU) | ((slottype[0U] << 6) & 0xC0U) | ((slottype[1U] >> 2) & 0x30U);
		payload[19U] = (payload[19U] & 0xF0U) | ((slottype[1U] >> 2) & 0x0FU);
		payload[20U] = (payload[20U] & 0x03U) | ((slottype[1U] << 6) & 0xC0U) | ((slottype[2U] >> 2) & 0x3CU);

	}
	// and encode
	bptc.encode(lc, payload);

	// and append
	buffer->Append(payload, sizeof(payload));
}

void CDmrmmdvmProtocol::AppendTerminatorLCToBuffer(CBuffer *buffer, uint32_t uiSrcId, uint32_t uiDstId) const
{
	uint8_t payload[33];

	// fill payload
	CBPTC19696 bptc;
	memset(payload, 0, sizeof(payload));
	// LC data
	uint8_t lc[12];
	{
		memset(lc, 0, sizeof(lc));
		// uiDstId
		lc[3] = (uint8_t)LOBYTE(HIWORD(uiDstId));
		lc[4] = (uint8_t)HIBYTE(LOWORD(uiDstId));
		lc[5] = (uint8_t)LOBYTE(LOWORD(uiDstId));
		// uiSrcId
		lc[6] = (uint8_t)LOBYTE(HIWORD(uiSrcId));
		lc[7] = (uint8_t)HIBYTE(LOWORD(uiSrcId));
		lc[8] = (uint8_t)LOBYTE(LOWORD(uiSrcId));
		// parity
		uint8_t parity[4];
		CRS129::encode(lc, 9, parity);
		lc[9]  = parity[2] ^ DMR_TERMINATOR_WITH_LC_CRC_MASK;
		lc[10] = parity[1] ^ DMR_TERMINATOR_WITH_LC_CRC_MASK;
		lc[11] = parity[0] ^ DMR_TERMINATOR_WITH_LC_CRC_MASK;
	}
	// sync
	memcpy(payload+13, g_DmrSyncBSData, sizeof(g_DmrSyncBSData));
	// slot type
	{
		// slot type
		uint8_t slottype[3];
		memset(slottype, 0, sizeof(slottype));
		slottype[0]  = (DMRMMDVM_REFLECTOR_COLOUR << 4) & 0xF0;
		slottype[0] |= (DMR_DT_TERMINATOR_WITH_LC  << 0) & 0x0FU;
		CGolay2087::encode(slottype);
		payload[12U] = (payload[12U] & 0xC0U) | ((slottype[0U] >> 2) & 0x3FU);
		payload[13U] = (payload[13U] & 0x0FU) | ((slottype[0U] << 6) & 0xC0U) | ((slottype[1U] >> 2) & 0x30U);
		payload[19U] = (payload[19U] & 0xF0U) | ((slottype[1U] >> 2) & 0x0FU);
		payload[20U] = (payload[20U] & 0x03U) | ((slottype[1U] << 6) & 0xC0U) | ((slottype[2U] >> 2) & 0x3CU);
	}
	// and encode
	bptc.encode(lc, payload);

	// and append
	buffer->Append(payload, sizeof(payload));
}

void CDmrmmdvmProtocol::ReplaceEMBInBuffer(CBuffer *buffer, uint8_t uiDmrPacketId) const
{
	// voice packet A ?
	if ( uiDmrPacketId == 0 )
	{
		// sync
		buffer->ReplaceAt(33, (uint8_t)(buffer->at(33) | (g_DmrSyncBSVoice[0] & 0x0F)));
		buffer->ReplaceAt(34, g_DmrSyncBSVoice+1, 5);
		buffer->ReplaceAt(39, (uint8_t)(buffer->at(39) | (g_DmrSyncBSVoice[6] & 0xF0)));
	}
	// voice packet B,C,D,E ?
	else if ( (uiDmrPacketId >= 1) && (uiDmrPacketId <= 4 ) )
	{
		// EMB LC
		uint8_t emb[2];
		emb[0]  = (DMRMMDVM_REFLECTOR_COLOUR << 4) & 0xF0;
		//emb[0] |= PI ? 0x08U : 0x00;
		//emb[0] |= (LCSS << 1) & 0x06;
		emb[1]  = 0x00;
		// encode
		CQR1676::encode(emb);
		// and append
		buffer->ReplaceAt(33, (uint8_t)((buffer->at(33) & 0xF0) | ((emb[0U] >> 4) & 0x0F)));
		buffer->ReplaceAt(34, (uint8_t)((buffer->at(34) & 0x0F) | ((emb[0U] << 4) & 0xF0)));
		buffer->ReplaceAt(34, (uint8_t)(buffer->at(34) & 0xF0));
		buffer->ReplaceAt(35, (uint8_t)0);
		buffer->ReplaceAt(36, (uint8_t)0);
		buffer->ReplaceAt(37, (uint8_t)0);
		buffer->ReplaceAt(38, (uint8_t)(buffer->at(38) & 0x0F));
		buffer->ReplaceAt(38, (uint8_t)((buffer->at(38) & 0xF0) | ((emb[1U] >> 4) & 0x0F)));
		buffer->ReplaceAt(39, (uint8_t)((buffer->at(39) & 0x0F) | ((emb[1U] << 4) & 0xF0)));
	}
	// voice packet F
	else
	{
		// nullptr
		uint8_t emb[2];
		emb[0]  = (DMRMMDVM_REFLECTOR_COLOUR << 4) & 0xF0;
		//emb[0] |= PI ? 0x08U : 0x00;
		//emb[0] |= (LCSS << 1) & 0x06;
		emb[1]  = 0x00;
		// encode
		CQR1676::encode(emb);
		// and append
		buffer->ReplaceAt(33, (uint8_t)((buffer->at(33) & 0xF0) | ((emb[0U] >> 4) & 0x0F)));
		buffer->ReplaceAt(34, (uint8_t)((buffer->at(34) & 0x0F) | ((emb[0U] << 4) & 0xF0)));
		buffer->ReplaceAt(34, (uint8_t)(buffer->at(34) & 0xF0));
		buffer->ReplaceAt(35, (uint8_t)0);
		buffer->ReplaceAt(36, (uint8_t)0);
		buffer->ReplaceAt(37, (uint8_t)0);
		buffer->ReplaceAt(38, (uint8_t)(buffer->at(38) & 0x0F));
		buffer->ReplaceAt(38, (uint8_t)((buffer->at(38) & 0xF0) | ((emb[1U] >> 4) & 0x0F)));
		buffer->ReplaceAt(39, (uint8_t)((buffer->at(39) & 0x0F) | ((emb[1U] << 4) & 0xF0)));
	}
}

void CDmrmmdvmProtocol::AppendDmrIdToBuffer(CBuffer *buffer, uint32_t id) const
{
	buffer->Append((uint8_t)LOBYTE(HIWORD(id)));
	buffer->Append((uint8_t)HIBYTE(LOWORD(id)));
	buffer->Append((uint8_t)LOBYTE(LOWORD(id)));
}

void CDmrmmdvmProtocol::AppendDmrRptrIdToBuffer(CBuffer *buffer, uint32_t id) const
{
	buffer->Append((uint8_t)HIBYTE(HIWORD(id)));
	buffer->Append((uint8_t)LOBYTE(HIWORD(id)));
	buffer->Append((uint8_t)HIBYTE(LOWORD(id)));
	buffer->Append((uint8_t)LOBYTE(LOWORD(id)));
}
