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
#include "DMRPlusClient.h"
#include "DMRPlusProtocol.h"
#include "BPTC19696.h"
#include "RS129.h"
#include "Golay2087.h"
#include "QR1676.h"

////////////////////////////////////////////////////////////////////////////////////////
// constants

static uint8_t g_DmrSyncBSVoice[]    = { 0x07,0x55,0xFD,0x7D,0xF7,0x5F,0x70 };
static uint8_t g_DmrSyncBSData[]     = { 0x0D,0xFF,0x57,0xD7,0x5D,0xF5,0xD0 };
static uint8_t g_DmrSyncMSVoice[]    = { 0x07,0xF7,0xD5,0xDD,0x57,0xDF,0xD0 };
static uint8_t g_DmrSyncMSData[]     = { 0x0D,0x5D,0x7F,0x77,0xFD,0x75,0x70 };


////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CDmrplusProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	// base class
	if (! CProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	// update time
	m_LastKeepaliveTime.start();

	// random number generator
	time_t t;
	::srand((unsigned) time(&t));

	// done
	return true;
}



////////////////////////////////////////////////////////////////////////////////////////
// task

void CDmrplusProtocol::Task(void)
{
	CBuffer   Buffer;
	CIp       Ip;
	CCallsign Callsign;
	char      ToLinkModule;
	std::unique_ptr<CDvHeaderPacket>               Header;
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
		// crack the packet
		if ( IsValidDvFramePacket(Ip, Buffer, Frames) )
		{
			for ( int i = 0; i < 3; i++ )
			{
				OnDvFramePacketIn(Frames[i], &Ip);
			}
		}
		else if ( IsValidDvHeaderPacket(Ip, Buffer, Header) )
		{
			// callsign muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::dmrplus) )
			{
				// handle it
				OnDvHeaderPacketIn(Header, Ip);
			}
		}
		else if ( IsValidConnectPacket(Buffer, &Callsign, &ToLinkModule, Ip) )
		{
			//std::cout << "DMRplus keepalive/connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << std::endl;

			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::dmrplus) )
			{
				// acknowledge the request
				EncodeConnectAckPacket(&Buffer);
				Send(Buffer, Ip);

				// add client if needed
				CClients *clients = g_Reflector.GetClients();
				std::shared_ptr<CClient>client = clients->FindClient(Callsign, Ip, EProtocol::dmrplus);
				// client already connected ?
				if ( client == nullptr )
				{
					std::cout << "DMRplus connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << std::endl;

					// create the client and append
					clients->AddClient(std::make_shared<CDmrplusClient>(Callsign, Ip, ToLinkModule));
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
				EncodeConnectNackPacket(&Buffer);
				Send(Buffer, Ip);
			}

		}
		else if ( IsValidDisconnectPacket(Buffer, &Callsign, &ToLinkModule) )
		{
			std::cout << "DMRplus disconnect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << std::endl;

			// find client & remove it
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::dmrplus);
			if ( client != nullptr )
			{
				clients->RemoveClient(client);
			}
			g_Reflector.ReleaseClients();
		}
		else
		{
			std::string title("Unknown DMR+ packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();


	// keep client alive
	if ( m_LastKeepaliveTime.time() > DMRPLUS_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CDmrplusProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
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
		CCallsign my(Header->GetMyCallsign());
		CCallsign rpt1(Header->GetRpt1Callsign());
		CCallsign rpt2(Header->GetRpt2Callsign());

		// no stream open yet, open a new one
		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::dmrplus);
		if ( client )
		{
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
		g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2, EProtocol::dmrplus);
		g_Reflector.ReleaseUsers();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CDmrplusProtocol::HandleQueue(void)
{
	while (! m_Queue.IsEmpty())
	{
		// get the packet
		auto packet = m_Queue.Pop();

		// get our sender's id
		const auto mod = packet->GetPacketModule();

		// encode
		CBuffer buffer;

		// check if it's header
		if ( packet->IsDvHeader() )
		{
			// update local stream cache
			// this relies on queue feeder setting valid module id
			m_StreamsCache[mod].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet.get());
			m_StreamsCache[mod].m_uiSeqId = 4;

			// encode it
			EncodeDMRPlusHeaderPacket((const CDvHeaderPacket &)*packet.get(), &buffer);
		}
		else
		{
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
				EncodeDMRPlusPacket(m_StreamsCache[mod].m_dvHeader, m_StreamsCache[mod].m_dvFrame0, m_StreamsCache[mod].m_dvFrame1, (const CDvFramePacket &)*packet.get(), m_StreamsCache[mod].m_uiSeqId, &buffer);
				m_StreamsCache[mod].m_uiSeqId = GetNextSeqId(m_StreamsCache[mod].m_uiSeqId);
				break;
			default:
				break;
			}

		}

		// send it
		if ( buffer.size() > 0 )
		{
			// and push it to all our clients linked to the module and who are not streaming in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::dmrplus, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetPacketModule()) )
				{
					// no, send the packet
					Send(buffer, client->GetIp());
				}
			}
			g_Reflector.ReleaseClients();

			// debug
			//buffer.DebugDump(g_Reflector.m_DebugFile);
		}
	}
}

void CDmrplusProtocol::SendBufferToClients(const CBuffer &buffer, uint8_t module)
{
	if ( buffer.size() > 0 )
	{
		// and push it to all our clients linked to the module and who are not streaming in
		CClients *clients = g_Reflector.GetClients();
		auto it = clients->begin();
		std::shared_ptr<CClient>client = nullptr;
		while ( (client = clients->FindNextClient(EProtocol::dmrplus, it)) != nullptr )
		{
			// is this client busy ?
			if ( !client->IsAMaster() && (client->GetReflectorModule() == module) )
			{
				// no, send the packet
				Send(buffer, client->GetIp());
			}
		}
		g_Reflector.ReleaseClients();

		// debug
		//buffer.DebugDump(g_Reflector.m_DebugFile);
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CDmrplusProtocol::HandleKeepalives(void)
{
	// DMRplus protocol keepalive request is client tasks
	// here, just check that all clients are still alive
	// and disconnect them if not

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::dmrplus, it)) != nullptr )
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
			//CBuffer disconnect;
			//EncodeDisconnectPacket(&disconnect, client);
			//Send(disconnect, client->GetIp());

			// remove it
			std::cout << "DMRplus client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}

	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CDmrplusProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign, char *reflectormodule, const CIp &Ip)
{
	bool valid = false;
	if ( Buffer.size() == 31 )
	{
		char sz[9];
		memcpy(sz, Buffer.data(), 8);
		sz[8] = 0;
		uint32_t dmrid = atoi(sz);
		callsign->SetDmrid(dmrid, true);
		callsign->SetCSModule(DMRPLUS_MODULE_ID);
		memcpy(sz, &Buffer.data()[8], 4);
		sz[4] = 0;
		*reflectormodule = DmrDstIdToModule(atoi(sz));
		valid = (callsign->IsValid() && (std::isupper(*reflectormodule) || (*reflectormodule == ' ')) );
		if ( !valid)
		{
			std::cout << "Invalid callsign in DMR+ connect packet from IP: " << Ip << " CS:" << *callsign << " DMRID:" << callsign->GetDmrid() << " ReflectorModule:" << *reflectormodule << std::endl;
		}
	}
	return valid;
}

bool CDmrplusProtocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign, char *reflectormodule)
{
	bool valid = false;
	if ( Buffer.size() == 32 )
	{
		char sz[9];
		memcpy(sz, Buffer.data(), 8);
		sz[8] = 0;
		uint32_t dmrid = atoi(sz);
		callsign->SetDmrid(dmrid, true);
		callsign->SetCSModule(DMRPLUS_MODULE_ID);
		*reflectormodule = Buffer.data()[11] - '0' + 'A';
		valid = (callsign->IsValid() && std::isupper(*reflectormodule));
	}
	return valid;
}

bool CDmrplusProtocol::IsValidDvHeaderPacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &Header)
{
	uint8_t uiPacketType = Buffer.data()[8];
	if ( (Buffer.size() == 72)  && ( uiPacketType == 2 ) )
	{
		// frame details
		uint8_t uiSlot = (Buffer.data()[16] == 0x22) ? DMR_SLOT2 : DMR_SLOT1;
		uint8_t uiCallType = (Buffer.data()[62] == 1) ? DMR_GROUP_CALL : DMR_PRIVATE_CALL;
		uint8_t uiColourCode = Buffer.data()[20] & 0x0F;
		if ( (uiSlot == DMRPLUS_REFLECTOR_SLOT) && (uiCallType == DMR_GROUP_CALL) && (uiColourCode == DMRPLUS_REFLECTOR_COLOUR) )
		{
			// more frames details
			//uint8_t uiSeqId = Buffer.data()[4];
			//uint8_t uiVoiceSeq = (Buffer.data()[18] & 0x0F) - 7; // aka slot type
			uint32_t uiDstId = *(uint32_t *)(&Buffer.data()[64]) & 0x00FFFFFF;
			uint32_t uiSrcId = *(uint32_t *)(&Buffer.data()[68]) & 0x00FFFFFF;

			// build DVHeader
			CCallsign csMY =  CCallsign("", uiSrcId);
			CCallsign rpt1 = CCallsign("", uiSrcId);
			rpt1.SetCSModule(DMRPLUS_MODULE_ID);
			CCallsign rpt2 = m_ReflectorCallsign;
			rpt2.SetCSModule(DmrDstIdToModule(uiDstId));
			uint32_t uiStreamId = IpToStreamId(Ip);

			// and packet
			Header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(uiSrcId, CCallsign("CQCQCQ"), rpt1, rpt2, uiStreamId, 0, 0));
			if (Header && Header->IsValid())
				return true;
		}
	}
	return false;
}

bool CDmrplusProtocol::IsValidDvFramePacket(const CIp &Ip, const CBuffer &Buffer, std::array<std::unique_ptr<CDvFramePacket>, 3> &frames)
{
	uint8_t uiPacketType = Buffer.data()[8];
	if ( (Buffer.size() == 72)  && ((uiPacketType == 1) || (uiPacketType == 3)) )
	{
		// frame details
		uint8_t uiSlot = (Buffer.data()[16] == 0x22) ? DMR_SLOT2 : DMR_SLOT1;
		uint8_t uiCallType = (Buffer.data()[62] == 1) ? DMR_GROUP_CALL : DMR_PRIVATE_CALL;
		uint8_t uiColourCode = Buffer.data()[20] & 0x0F;
		if ( (uiSlot == DMRPLUS_REFLECTOR_SLOT) && (uiCallType == DMR_GROUP_CALL) && (uiColourCode == DMRPLUS_REFLECTOR_COLOUR) )
		{
			// more frames details
			//uint8_t uiSeqId = Buffer.data()[4];
			uint8_t uiVoiceSeq = (Buffer.data()[18] & 0x0F) - 7; // aka slot type
			//uint32_t uiDstId = *(uint32_t *)(&Buffer.data()[64]) & 0x00FFFFFF;
			//uint32_t uiSrcId = *(uint32_t *)(&Buffer.data()[68]) & 0x00FFFFFF;

			// crack payload
			uint8_t dmrframe[33];
			uint8_t dmr3ambe[27];
			uint8_t dmrambe[9];
			uint8_t dmrsync[7];
			// get the 33 bytes ambe
			memcpy(dmrframe, &(Buffer.data()[26]), 33);
			// handle endianness
			SwapEndianess(dmrframe, sizeof(dmrframe));
			// extract the 3 ambe frames
			memcpy(dmr3ambe, dmrframe, 14);
			dmr3ambe[13] &= 0xF0;
			dmr3ambe[13] |= (dmrframe[19] & 0x0F);
			memcpy(&dmr3ambe[14], &dmrframe[20], 13);
			// extract sync
			dmrsync[0] = dmrframe[13] & 0x0F;
			memcpy(&dmrsync[1], &dmrframe[14], 5);
			dmrsync[6] = dmrframe[19] & 0xF0;

			// and create 3 dv frames
			uint32_t uiStreamId = IpToStreamId(Ip);
			// frame1
			memcpy(dmrambe, &dmr3ambe[0], 9);
			frames[0] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 1, false));

			// frame2
			memcpy(dmrambe, &dmr3ambe[9], 9);
			frames[1] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 2, false));

			// frame3
			memcpy(dmrambe, &dmr3ambe[18], 9);
			if ( uiPacketType == 3 )
			{
				frames[2] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 3, true));
			}
			else
			{
				frames[2] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(dmrambe, dmrsync, uiStreamId, uiVoiceSeq, 3, false));
			}

			// check
			if (frames[0] && frames[1] && frames[2])
				return true;
		}
	}
	return false;
}


////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

void CDmrplusProtocol::EncodeConnectAckPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 'A','C','K',' ','O','K',0x0A,0x00 };
	Buffer->Set(tag, sizeof(tag));
}

void CDmrplusProtocol::EncodeConnectNackPacket(CBuffer *Buffer)
{
	uint8_t tag[] = { 'N','A','K',' ','O','K',0x0A,0x00 };
	Buffer->Set(tag, sizeof(tag));
}

bool CDmrplusProtocol::EncodeDMRPlusHeaderPacket(const CDvHeaderPacket &Packet, CBuffer *Buffer) const
{
	uint8_t tag[]	= { 0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,0x05,0x01,0x02,0x00,0x00,0x00 };
	Buffer->Set(tag, sizeof(tag));

	// uiSeqId
	//Buffer->ReplaceAt(4, 2);
	// uiPktType
	//Buffer->ReplaceAt(8, 2);
	// uiSlot
	Buffer->Append((uint16_t)((DMRPLUS_REFLECTOR_SLOT == DMR_SLOT1) ? 0x1111 : 0x2222));
	// uiSlotType
	Buffer->Append((uint16_t)0xEEEE);
	// uiColourCode
	uint8_t uiColourCode = DMRPLUS_REFLECTOR_COLOUR | (DMRPLUS_REFLECTOR_COLOUR << 4);
	Buffer->Append((uint8_t)uiColourCode);
	Buffer->Append((uint8_t)uiColourCode);
	// uiFrameType
	Buffer->Append((uint16_t)0x1111);
	// reserved
	Buffer->Append((uint16_t)0x0000);
	// payload
	uint32_t uiSrcId = Packet.GetMyCallsign().GetDmrid()  & 0x00FFFFFF;
	uint32_t uiDstId = ModuleToDmrDestId(Packet.GetRpt2Module()) & 0x00FFFFFF;
	Buffer->Append((uint8_t)0x00, 34);
	Buffer->ReplaceAt(36, HIBYTE(HIWORD(uiSrcId)));
	Buffer->ReplaceAt(38, LOBYTE(HIWORD(uiSrcId)));
	Buffer->ReplaceAt(40, HIBYTE(LOWORD(uiSrcId)));
	Buffer->ReplaceAt(42, LOBYTE(LOWORD(uiSrcId)));

	// reserved
	Buffer->Append((uint16_t)0x0000);
	// uiCallType
	Buffer->Append((uint8_t)0x01);
	// reserved
	Buffer->Append((uint8_t)0x00);
	// uiDstId
	Buffer->Append(uiDstId);
	// uiSrcId
	Buffer->Append(uiSrcId);

	// done
	return true;
}

void CDmrplusProtocol::EncodeDMRPlusPacket(const CDvHeaderPacket &Header, const CDvFramePacket &DvFrame0, const CDvFramePacket &DvFrame1, const CDvFramePacket &DvFrame2, uint8_t seqid, CBuffer *Buffer) const
{

	uint8_t tag[]	= { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
					0x00,0x05,0x01,0x02,0x00,0x00,0x00
				  } ;
	Buffer->Set(tag, sizeof(tag));

	// uiSeqId
	Buffer->ReplaceAt(4, seqid);
	// uiPktType
	//Buffer->ReplaceAt(8, 1);
	// uiSlot
	Buffer->Append((uint16_t)((DMRPLUS_REFLECTOR_SLOT == DMR_SLOT1) ? 0x1111 : 0x2222));
	// uiVoiceSeq
	uint8_t uiVoiceSeq = (DvFrame0.GetDmrPacketId() + 7) | ((DvFrame0.GetDmrPacketId() + 7) << 4);
	Buffer->Append((uint8_t)uiVoiceSeq);
	Buffer->Append((uint8_t)uiVoiceSeq);
	// uiColourCode
	uint8_t uiColourCode = DMRPLUS_REFLECTOR_COLOUR | (DMRPLUS_REFLECTOR_COLOUR << 4);
	Buffer->Append((uint8_t)uiColourCode);
	Buffer->Append((uint8_t)uiColourCode);
	// uiFrameType
	Buffer->Append((uint16_t)0x1111);
	// reserved
	Buffer->Append((uint16_t)0x0000);

	// payload
	uint32_t uiSrcId = Header.GetMyCallsign().GetDmrid()  & 0x00FFFFFF;
	uint32_t uiDstId = ModuleToDmrDestId(Header.GetRpt2Module()) & 0x00FFFFFF;
	// frame0
	Buffer->ReplaceAt(26, DvFrame0.GetCodecData(ECodecType::dmr), 9);
	// 1/2 frame1
	Buffer->ReplaceAt(35, DvFrame1.GetCodecData(ECodecType::dmr), 5);
	Buffer->ReplaceAt(39, (uint8_t)(Buffer->at(39) & 0xF0));
	// 1/2 frame1
	Buffer->ReplaceAt(45, DvFrame1.GetCodecData(ECodecType::dmr)+4, 5);
	Buffer->ReplaceAt(45, (uint8_t)(Buffer->at(45) & 0x0F));
	// frame2
	Buffer->ReplaceAt(50, DvFrame2.GetCodecData(ECodecType::dmr), 9);

	// sync or embedded signaling
	ReplaceEMBInBuffer(Buffer, DvFrame0.GetDmrPacketId());

	// reserved
	Buffer->Append((uint16_t)0x0000);
	Buffer->Append((uint8_t)0x00);
	// uiCallType
	Buffer->Append((uint8_t)0x01);
	// reserved
	Buffer->Append((uint8_t)0x00);
	// uiDstId
	Buffer->Append(uiDstId);
	// uiSrcId
	Buffer->Append(uiSrcId);

	// handle indianess
	SwapEndianess(&(Buffer->data()[26]), 34);
}

void CDmrplusProtocol::SwapEndianess(uint8_t *buffer, int len) const
{
	for ( int i = 0; i < len; i += 2 )
	{
		uint8_t t = buffer[i];
		buffer[i] = buffer[i+1];
		buffer[i+1] = t;
	}
}


////////////////////////////////////////////////////////////////////////////////////////
// SeqId helper

uint8_t CDmrplusProtocol::GetNextSeqId(uint8_t uiSeqId) const
{
	return (uiSeqId + 1) & 0xFF;
}

////////////////////////////////////////////////////////////////////////////////////////
// DestId to Module helper

char CDmrplusProtocol::DmrDstIdToModule(uint32_t tg) const
{
	// is it a 4xxx ?
	if (tg > 4000 && tg < 4027) {
		char mod = 'A' + (tg - 4001U);
		if (g_Reflector.IsValidModule(mod))
		{
			return mod;
		}
	}
	return ' ';
}

uint32_t CDmrplusProtocol::ModuleToDmrDestId(char m) const
{
	return (uint32_t)(m - 'A')+4001;
}

////////////////////////////////////////////////////////////////////////////////////////
// Buffer & LC helpers

void CDmrplusProtocol::AppendVoiceLCToBuffer(CBuffer *buffer, uint32_t uiSrcId) const
{
	uint8_t payload[34];

	// fill payload
	CBPTC19696 bptc;
	memset(payload, 0, sizeof(payload));
	// LC data
	uint8_t lc[12];
	{
		memset(lc, 0, sizeof(lc));
		// uiDstId = TG9
		lc[5] = 9;
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
		slottype[0]  = (DMRPLUS_REFLECTOR_COLOUR << 4) & 0xF0;
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

void CDmrplusProtocol::ReplaceEMBInBuffer(CBuffer *buffer, uint8_t uiDmrPacketId) const
{
	// voice packet A ?
	if ( uiDmrPacketId == 0 )
	{
		// sync
		buffer->ReplaceAt(39, (uint8_t)(buffer->at(39) | (g_DmrSyncBSVoice[0] & 0x0F)));
		buffer->ReplaceAt(40, g_DmrSyncBSVoice+1, 5);
		buffer->ReplaceAt(45, (uint8_t)(buffer->at(45) | (g_DmrSyncBSVoice[6] & 0xF0)));
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
		buffer->ReplaceAt(39, (uint8_t)((buffer->at(39) & 0xF0) | ((emb[0U] >> 4) & 0x0F)));
		buffer->ReplaceAt(40, (uint8_t)((buffer->at(40) & 0x0F) | ((emb[0U] << 4) & 0xF0)));
		buffer->ReplaceAt(40, (uint8_t)(buffer->at(40) & 0xF0));
		buffer->ReplaceAt(41, (uint8_t)0);
		buffer->ReplaceAt(42, (uint8_t)0);
		buffer->ReplaceAt(43, (uint8_t)0);
		buffer->ReplaceAt(44, (uint8_t)(buffer->at(44) & 0x0F));
		buffer->ReplaceAt(44, (uint8_t)((buffer->at(44) & 0xF0) | ((emb[1U] >> 4) & 0x0F)));
		buffer->ReplaceAt(45, (uint8_t)((buffer->at(45) & 0x0F) | ((emb[1U] << 4) & 0xF0)));
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
		buffer->ReplaceAt(39, (uint8_t)((buffer->at(39) & 0xF0) | ((emb[0U] >> 4) & 0x0F)));
		buffer->ReplaceAt(40, (uint8_t)((buffer->at(40) & 0x0F) | ((emb[0U] << 4) & 0xF0)));
		buffer->ReplaceAt(40, (uint8_t)(buffer->at(40) & 0xF0));
		buffer->ReplaceAt(41, (uint8_t)0);
		buffer->ReplaceAt(42, (uint8_t)0);
		buffer->ReplaceAt(43, (uint8_t)0);
		buffer->ReplaceAt(44, (uint8_t)(buffer->at(44) & 0x0F));
		buffer->ReplaceAt(44, (uint8_t)((buffer->at(44) & 0xF0) | ((emb[1U] >> 4) & 0x0F)));
		buffer->ReplaceAt(45, (uint8_t)((buffer->at(45) & 0x0F) | ((emb[1U] << 4) & 0xF0)));
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// uiStreamId helpers


// uiStreamId helpers
uint32_t CDmrplusProtocol::IpToStreamId(const CIp &ip) const
{
	return ip.GetAddr() ^ (uint32_t)(MAKEDWORD(ip.GetPort(), ip.GetPort()));
}
