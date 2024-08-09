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
#include "NXDNClient.h"
#include "NXDNProtocol.h"
#include "YSFDefines.h"
#include "Golay24128.h"
#include "Global.h"

const uint8_t NXDN_LICH_RFCT_RDCH			= 2U;
const uint8_t NXDN_LICH_USC_SACCH_NS		= 0U;
const uint8_t NXDN_LICH_USC_SACCH_SS		= 2U;
const uint8_t NXDN_LICH_STEAL_FACCH			= 0U;
const uint8_t NXDN_LICH_STEAL_NONE			= 3U;
const uint8_t NXDN_LICH_DIRECTION_INBOUND	= 0U;
const uint8_t NXDN_MESSAGE_TYPE_VCALL       = 1U;
const uint8_t NXDN_MESSAGE_TYPE_TX_REL      = 8U;

const int dvsi_interleave[49] = {
	0, 3, 6,  9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 41, 43, 45, 47,
	1, 4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 42, 44, 46, 48,
	2, 5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38
};

////////////////////////////////////////////////////////////////////////////////////////
// constructor
CNXDNProtocol::CNXDNProtocol()
{
	m_seqNo = 0;
}

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CNXDNProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	// config value
	m_ReflectorId = g_Configure.GetUnsigned(g_Keys.nxdn.reflectorid);
	m_AutolinkModule = g_Configure.GetAutolinkModule(g_Keys.nxdn.autolinkmod);

	// base class
	if (! CProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	// update time
	m_LastKeepaliveTime.start();

	return true;
}

void CNXDNProtocol::Close(void)
{
	// base class
	CProtocol::Close();
}

////////////////////////////////////////////////////////////////////////////////////////
// task

void CNXDNProtocol::Task(void)
{
	CBuffer    Buffer;
	CIp        Ip;
	CCallsign  Callsign;

	std::unique_ptr<CDvHeaderPacket>               Header;
	std::array<std::unique_ptr<CDvFramePacket>, 4> Frames;

	// handle incoming packets
#if NXDN_IPV6==true
#if NXDN_IPV4==true
	if ( ReceiveDS(Buffer, Ip, 20) )
#else
	if ( Receive6(Buffer, Ip, 20) )
#endif
#else
	if ( Receive4(Buffer, Ip, 20) )
#endif
	{
		// crack the packet
		if ( IsValidDvFramePacket(Ip, Buffer, Header, Frames) )
		{
			OnDvFramePacketIn(Frames[0], &Ip);
			OnDvFramePacketIn(Frames[1], &Ip);
			OnDvFramePacketIn(Frames[2], &Ip);
			OnDvFramePacketIn(Frames[3], &Ip);
		}
		else if ( IsValidDvHeaderPacket(Ip, Buffer, Header) )
		{
			// node linked and callsign muted?
			if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, EProtocol::nxdn, Header->GetRpt2Module())  )
			{
				// handle it
				OnDvHeaderPacketIn(Header, Ip);
			}
		}
		else if ( IsValidDvLastFramePacket(Ip, Buffer) )
		{
			m_uiStreamId = 0;
		}
		else if ( IsValidConnectPacket(Buffer, &Callsign) )
		{
			// callsign authorized?
			if ( g_GateKeeper.MayLink(Callsign, Ip, EProtocol::nxdn) )
			{
				// add client if needed
				CClients *clients = g_Reflector.GetClients();
				std::shared_ptr<CClient>client = clients->FindClient(Callsign, Ip, EProtocol::nxdn);
				// client already connected ?
				if ( client == nullptr )
				{
					std::cout << "NXDN connect packet from " << Callsign << " at " << Ip << std::endl;

					// create the client
					auto newclient = std::make_shared<CNXDNClient>(Callsign, Ip);

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

				// acknowledge the request -- NXDNReflector simply echoes the packet
				Send(Buffer, Ip);
				// and done
				g_Reflector.ReleaseClients();
			}
		}
		else if ( IsValidDisconnectPacket(Buffer) )
		{
			std::cout << "NXDN disconnect packet from " << Ip << std::endl;

			// find client
			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient>client = clients->FindClient(Ip, EProtocol::nxdn);
			if ( client != nullptr )
			{
				// remove it
				clients->RemoveClient(client);
			}
			g_Reflector.ReleaseClients();
		}
		else
		{
#ifdef DEBUG
			std::string title("Unknown NXDN packet from ");
			title += Ip.GetAddress();
			Buffer.Dump(title);
#endif
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep client alive
	if ( m_LastKeepaliveTime.time() > NXDN_KEEPALIVE_PERIOD )
	{
		//
		HandleKeepalives();

		// update time
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CNXDNProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
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

		// find this client
		std::shared_ptr<CClient>client = g_Reflector.GetClients()->FindClient(Ip, EProtocol::nxdn);
		if ( client )
		{
			// get client callsign
			rpt1 = client->GetCallsign();
			// get module it's linked to
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
		if ( g_Reflector.IsValidModule(rpt2.GetCSModule()) )
		{
			g_Reflector.GetUsers()->Hearing(my, rpt1, rpt2);
			g_Reflector.ReleaseUsers();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CNXDNProtocol::HandleQueue(void)
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
			m_StreamsCache[mod].m_dvHeader = CDvHeaderPacket((CDvHeaderPacket &)*packet.get());
			m_StreamsCache[mod].m_iSeqCounter = 0;

			// encode it
			EncodeNXDNHeaderPacket((CDvHeaderPacket &)*packet.get(), buffer);
		}
		// check if it's a last frame
		else if ( packet->IsLastPacket() )
		{
			// encode it
			EncodeNXDNHeaderPacket((CDvHeaderPacket &)*packet.get(), buffer, true);
		}
		// otherwise, just a regular DV frame
		else
		{
			// update local stream cache or send triplet when needed
			uint8_t pid = packet->GetNXDNPacketId();
			if (pid <= 3)
			{
				m_StreamsCache[mod].m_dvFrames[pid] = CDvFramePacket((CDvFramePacket &)*packet.get());
				if ( pid == 3 )
				{
					EncodeNXDNPacket(m_StreamsCache[mod].m_dvHeader, m_StreamsCache[mod].m_iSeqCounter++, m_StreamsCache[mod].m_dvFrames, buffer);
				}
			}
		}

		// send it
		if ( buffer.size() > 0 )
		{
			// and push it to all our clients linked to the module and who are not streaming in
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient>client = nullptr;
			while ( (client = clients->FindNextClient(EProtocol::nxdn, it)) != nullptr )
			{
				// is this client busy ?
				if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetPacketModule()) )
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
// keepalive helpers

void CNXDNProtocol::HandleKeepalives(void)
{
	// YSF protocol keepalive request is client tasks
	// here, just check that all clients are still alive
	// and disconnect them if not

	// iterate on clients
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient>client = nullptr;
	while ( (client = clients->FindNextClient(EProtocol::nxdn, it)) != nullptr )
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
			std::cout << "NXDN client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}

	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// DV packet decoding helpers

bool CNXDNProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
	uint8_t tag[] = { 'N','X','D','N','P' };

	bool valid = false;

	if ( (Buffer.size() == 17) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		callsign->SetCallsign(Buffer.data()+5, 8);
		valid = (callsign->IsValid());
	}
	return valid;
}

bool CNXDNProtocol::IsValidDisconnectPacket(const CBuffer &Buffer)
{
	uint8_t tag[] = { 'N','X','D','N','U' };

	if ( (Buffer.size() == 17) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
	{
		return true;
	}
	return false;
}

bool CNXDNProtocol::IsValidDvHeaderPacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	if(!memcmp(Buffer.data(), "NXDND", 5) && (Buffer.size() == 43) && (Buffer.data()[10] == NXDN_LICH_USC_SACCH_NS) && (Buffer.data()[9] == 1) )
	{
		auto stream = GetStream(m_uiStreamId, &Ip);
		if ( !stream )
		{
			uint16_t uiSrcId = ((Buffer.data()[5] << 8) & 0xff00) | (Buffer.data()[6] & 0xff);
			m_uiStreamId = static_cast<uint32_t>(::rand());
			CCallsign csMY = CCallsign("", 0, uiSrcId);
			CCallsign rpt1 = CCallsign("", 0, uiSrcId);
			CCallsign rpt2 = m_ReflectorCallsign;
			rpt1.SetCSModule(NXDN_MODULE_ID);
			rpt2.SetCSModule(' ');
			header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(csMY, CCallsign("CQCQCQ"), rpt1, rpt2, m_uiStreamId, false));
		}
		return true;
	}
	return false;
}

bool CNXDNProtocol::IsValidDvFramePacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header, std::array<std::unique_ptr<CDvFramePacket>, 4> &frames)
{
	if(!memcmp(Buffer.data(), "NXDND", 5) && (Buffer.size() == 43) && (Buffer.data()[10] != NXDN_LICH_USC_SACCH_NS) )
	{
		auto stream = GetStream(m_uiStreamId, &Ip);
		if ( !stream )
		{
			uint16_t uiSrcId = ((Buffer.data()[5] << 8) & 0xff00) | (Buffer.data()[6] & 0xff);
			m_uiStreamId = static_cast<uint32_t>(::rand());
			CCallsign csMY = CCallsign("", 0, uiSrcId);
			CCallsign rpt1 = CCallsign("", 0, uiSrcId);
			CCallsign rpt2 = m_ReflectorCallsign;
			rpt1.SetCSModule(NXDN_MODULE_ID);
			rpt2.SetCSModule(' ');
			header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(csMY, CCallsign("CQCQCQ"), rpt1, rpt2, m_uiStreamId, false));

			if ( g_GateKeeper.MayTransmit(header->GetMyCallsign(), Ip, EProtocol::nxdn, header->GetRpt2Module())  )
			{
				OnDvHeaderPacketIn(header, Ip);
			}
		}

		// get DV frames
		uint8_t   ambe49[7];

		uint8_t   ambe0[9];
		uint8_t   ambe1[9];
		uint8_t   ambe2[9];
		uint8_t   ambe3[9];

		memcpy(ambe49, Buffer.data() + 15, 7);
		encode(ambe49, ambe0);

		uint8_t t[7];
		const uint8_t *d = &(Buffer.data()[21]);
		for(int i = 0; i < 6; ++i){
			t[i] = d[i] << 1;
			t[i] |= (1 & (d[i+1] >> 7));
		}
		t[6] = d[6] << 1;

		memcpy(ambe49, t, 7);
		encode(ambe49, ambe1);

		memcpy(ambe49, Buffer.data() + 29, 7);
		encode(ambe49, ambe2);

		d = &(Buffer.data()[35]);
		for(int i = 0; i < 6; ++i){
			t[i] = d[i] << 1;
			t[i] |= (1 & (d[i+1] >> 7));
		}
		t[6] = d[6] << 1;

		memcpy(ambe49, t, 7);
		encode(ambe49, ambe3);

		// get DV frames
		frames[0] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(ambe0, m_uiStreamId, 0, false));
		frames[1] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(ambe1, m_uiStreamId, 1, false));
		frames[2] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(ambe2, m_uiStreamId, 2, false));
		frames[3] = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(ambe3, m_uiStreamId, 3, false));

		// check validity of packets
		if ( frames[0] && frames[0]->IsValid() && frames[1] && frames[1]->IsValid() && frames[2] && frames[2]->IsValid() && frames[3] && frames[3]->IsValid() )
			return true;
	}
	return false;
}

bool CNXDNProtocol::IsValidDvLastFramePacket(const CIp &Ip, const CBuffer &Buffer)
{
	if(!memcmp(Buffer.data(), "NXDND", 5) && (Buffer.size() == 43) && (Buffer.data()[10] == NXDN_LICH_USC_SACCH_NS) && ((Buffer.data()[9U] & 0x08) == 0x08) )
	{
			return true;
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// DV packet encoding helpers

bool CNXDNProtocol::EncodeNXDNHeaderPacket(const CDvHeaderPacket &Header, CBuffer &Buffer, bool islast)
{
	Buffer.resize(43);
	uint16_t NXDNId = Header.GetMyCallsign().GetNXDNid();
	uint16_t RptrId = m_ReflectorId;

	memcpy(Buffer.data(), "NXDND", 5);
	Buffer.data()[5U] = (NXDNId >> 8) & 0xFFU;
	Buffer.data()[6U] = (NXDNId >> 0) & 0xFFU;
	Buffer.data()[7U] = (RptrId >> 8) & 0xFFU;
	Buffer.data()[8U] = (RptrId >> 0) & 0xFFU;
	Buffer.data()[9U] = 0x01U;

	const uint8_t idle[3U] = {0x10, 0x00, 0x00};
	m_lich = 0;
	memset(m_sacch, 0, 5U);
	memset(m_layer3, 0, 22U);
	set_lich_rfct(NXDN_LICH_RFCT_RDCH);
	set_lich_fct(NXDN_LICH_USC_SACCH_NS);
	set_lich_option(NXDN_LICH_STEAL_FACCH);
	set_lich_dir(NXDN_LICH_DIRECTION_INBOUND);
	Buffer.data()[10U] = get_lich();

	set_sacch_ran(0x01);
	set_sacch_struct(0); //Single
	set_sacch_data(idle);
	get_sacch(&Buffer.data()[11U]);
	if(islast){
		set_layer3_msgtype(NXDN_MESSAGE_TYPE_TX_REL);
	}
	else{
		set_layer3_msgtype(NXDN_MESSAGE_TYPE_VCALL);
	}
	set_layer3_srcid(NXDNId);
	set_layer3_dstid(RptrId);
	set_layer3_grp(true);
	set_layer3_blks(0U);
	memcpy(&Buffer.data()[15U], m_layer3, 14U);
	memcpy(&Buffer.data()[29U], m_layer3, 14U);

	if (Buffer.data()[10U] == 0x81U || Buffer.data()[10U] == 0x83U) {
		Buffer.data()[9U] |= Buffer.data()[15U] == 0x01U ? 0x04U : 0x00U;
		Buffer.data()[9U] |= Buffer.data()[15U] == 0x08U ? 0x08U : 0x00U;
	}
	else if ((Buffer.data()[10U] & 0xF0U) == 0x90U) {
		Buffer.data()[9U] |= 0x02U;
		if (Buffer.data()[10U] == 0x90U || Buffer.data()[10U] == 0x92U || Buffer.data()[10U] == 0x9CU || Buffer.data()[10U] == 0x9EU) {
			Buffer.data()[9U] |= Buffer.data()[12U] == 0x09U ? 0x04U : 0x00U;
			Buffer.data()[9U] |= Buffer.data()[12U] == 0x08U ? 0x08U : 0x00U;
		}
	}

	return true;
}

bool CNXDNProtocol::EncodeNXDNPacket(const CDvHeaderPacket &Header, uint32_t seq, const CDvFramePacket *DvFrames, CBuffer &Buffer)
{
	uint8_t ambe[28];
	Buffer.resize(43);
	uint16_t NXDNId = Header.GetMyCallsign().GetNXDNid();
	uint16_t RptrId = m_ReflectorId;

	memcpy(Buffer.data(), "NXDND", 5);
	Buffer.data()[5U] = (NXDNId >> 8) & 0xFFU;
	Buffer.data()[6U] = (NXDNId >> 0) & 0xFFU;
	Buffer.data()[7U] = (RptrId >> 8) & 0xFFU;
	Buffer.data()[8U] = (RptrId >> 0) & 0xFFU;
	Buffer.data()[9U] = 0x01U;

	uint8_t msg[3U];
	m_lich = 0;
	memset(m_sacch, 0, 5U);
	memset(m_layer3, 0, 22U);
	set_lich_rfct(NXDN_LICH_RFCT_RDCH);
	set_lich_fct(NXDN_LICH_USC_SACCH_SS);
	set_lich_option(NXDN_LICH_STEAL_NONE);
	set_lich_dir(NXDN_LICH_DIRECTION_INBOUND);
	Buffer.data()[10U] = get_lich();

	set_sacch_ran(0x01);

	set_layer3_msgtype(NXDN_MESSAGE_TYPE_VCALL);
	set_layer3_srcid(NXDNId);
	set_layer3_dstid(RptrId);
	set_layer3_grp(true);
	set_layer3_blks(0U);

	switch(seq % 4){
	case 0:
		set_sacch_struct(3);
		layer3_encode(msg, 18U, 0U);
		set_sacch_data(msg);
		break;
	case 1:
		set_sacch_struct(2);
		layer3_encode(msg, 18U, 18U);
		set_sacch_data(msg);
		break;
	case 2:
		set_sacch_struct(1);
		layer3_encode(msg, 18U, 36U);
		set_sacch_data(msg);
		break;
	case 3:
		set_sacch_struct(0);
		layer3_encode(msg, 18U, 54U);
		set_sacch_data(msg);
		break;
	}
	get_sacch(&Buffer.data()[11U]);

	memset(ambe, 0, 28);
	for(int i = 0; i < 4; ++i){
		decode(DvFrames[i].GetCodecData(ECodecType::dmr), ambe+(i*7));
	}

	memcpy(&Buffer.data()[15], ambe, 7);
	for(int i = 0; i < 7; ++i){
		Buffer.data()[21+i] |= (ambe[7+i] >> 1);
		Buffer.data()[22+i] = (ambe[7+i] & 1) << 7;
	}
	Buffer.data()[28] |= (ambe[13] >> 2);

	memcpy(&Buffer.data()[29], &ambe[14], 7);
	for(int i = 0; i < 7; ++i){
		Buffer.data()[35+i] |= (ambe[21+i] >> 1);
		Buffer.data()[36+i] = (ambe[21+i] & 1) << 7;
	}
	Buffer.data()[41] |= (ambe[27] >> 2);

	return true;
}

void CNXDNProtocol::decode(const unsigned char* in, unsigned char* out) const
{
	unsigned int a = 0U;
	unsigned int MASK = 0x800000U;
	for (unsigned int i = 0U; i < 24U; i++, MASK >>= 1) {
		unsigned int aPos = DMR_A_TABLE[i];
		if (READ_BIT(in, aPos))
			a |= MASK;
	}

	unsigned int b = 0U;
	MASK = 0x400000U;
	for (unsigned int i = 0U; i < 23U; i++, MASK >>= 1) {
		unsigned int bPos = DMR_B_TABLE[i];
		if (READ_BIT(in, bPos))
			b |= MASK;
	}

	unsigned int c = 0U;
	MASK = 0x1000000U;
	for (unsigned int i = 0U; i < 25U; i++, MASK >>= 1) {
		unsigned int cPos = DMR_C_TABLE[i];
		if (READ_BIT(in, cPos))
			c |= MASK;
	}

	a >>= 12;

	// The PRNG
	b ^= (PRNG_TABLE[a] >> 1);
	b >>= 11;

	MASK = 0x000800U;
	for (unsigned int i = 0U; i < 12U; i++, MASK >>= 1) {
		unsigned int aPos = i + 0U;
		unsigned int bPos = i + 12U;
		WRITE_BIT(out, aPos, a & MASK);
		WRITE_BIT(out, bPos, b & MASK);
	}

	MASK = 0x1000000U;
	for (unsigned int i = 0U; i < 25U; i++, MASK >>= 1) {
		unsigned int cPos = i + 24U;
		WRITE_BIT(out, cPos, c & MASK);
	}
}

void CNXDNProtocol::encode(const unsigned char* in, unsigned char* out) const
{

	unsigned int aOrig = 0U;
	unsigned int bOrig = 0U;
	unsigned int cOrig = 0U;

	unsigned int MASK = 0x000800U;
	for (unsigned int i = 0U; i < 12U; i++, MASK >>= 1) {
		unsigned int n1 = i + 0U;
		unsigned int n2 = i + 12U;
		if (READ_BIT(in, n1))
			aOrig |= MASK;
		if (READ_BIT(in, n2))
			bOrig |= MASK;
	}

	MASK = 0x1000000U;
	for (unsigned int i = 0U; i < 25U; i++, MASK >>= 1) {
		unsigned int n = i + 24U;
		if (READ_BIT(in, n))
			cOrig |= MASK;
	}

	unsigned int a = CGolay24128::encode24128(aOrig);

	// The PRNG
	unsigned int p = PRNG_TABLE[aOrig] >> 1;

	unsigned int b = CGolay24128::encode23127(bOrig) >> 1;
	b ^= p;

	MASK = 0x800000U;
	for (unsigned int i = 0U; i < 24U; i++, MASK >>= 1) {
		unsigned int aPos = DMR_A_TABLE[i];
		WRITE_BIT(out, aPos, a & MASK);
	}

	MASK = 0x400000U;
	for (unsigned int i = 0U; i < 23U; i++, MASK >>= 1) {
		unsigned int bPos = DMR_B_TABLE[i];
		WRITE_BIT(out, bPos, b & MASK);
	}

	MASK = 0x1000000U;
	for (unsigned int i = 0U; i < 25U; i++, MASK >>= 1) {
		unsigned int cPos = DMR_C_TABLE[i];
		WRITE_BIT(out, cPos, cOrig & MASK);
	}
}

uint8_t CNXDNProtocol::get_lich_fct(uint8_t lich)
{
	return (lich >> 4) & 0x03U;
}

void CNXDNProtocol::set_lich_rfct(uint8_t rfct)
{
	m_lich &= 0x3FU;
	m_lich |= (rfct << 6) & 0xC0U;
}

void CNXDNProtocol::set_lich_fct(uint8_t fct)
{
	m_lich &= 0xCFU;
	m_lich |= (fct << 4) & 0x30U;
}

void CNXDNProtocol::set_lich_option(uint8_t o)
{
	m_lich &= 0xF3U;
	m_lich |= (o << 2) & 0x0CU;
}

void CNXDNProtocol::set_lich_dir(uint8_t d)
{
	m_lich &= 0xFDU;
	m_lich |= (d << 1) & 0x02U;
}

uint8_t CNXDNProtocol::get_lich()
{
	bool parity;
	switch (m_lich & 0xF0U) {
	case 0x80U:
	case 0xB0U:
		parity = true;
		break;
	default:
		parity = false;
	}
	if (parity)
		m_lich |= 0x01U;
	else
		m_lich &= 0xFEU;

	return m_lich;
}


void CNXDNProtocol::set_sacch_ran(uint8_t ran)
{
	m_sacch[0] &= 0xC0U;
	m_sacch[0] |= ran;
}

void CNXDNProtocol::set_sacch_struct(uint8_t s)
{
	m_sacch[0] &= 0x3FU;
	m_sacch[0] |= (s << 6) & 0xC0U;;
}

void CNXDNProtocol::set_sacch_data(const uint8_t *d)
{
	uint8_t offset = 8U;
	for (uint8_t i = 0U; i < 18U; i++, offset++) {
		bool b = READ_BIT(d, i);
		WRITE_BIT(m_sacch, offset, b);
	}
}

void CNXDNProtocol::get_sacch(uint8_t *d)
{
	memcpy(d, m_sacch, 4U);
	encode_crc6(d, 26);
}

void CNXDNProtocol::set_layer3_msgtype(uint8_t t)
{
	m_layer3[0] &= 0xC0U;
	m_layer3[0] |= t & 0x3FU;
}

void CNXDNProtocol::set_layer3_srcid(uint16_t src)
{
	m_layer3[3U] = (src >> 8) & 0xFF;
	m_layer3[4U] = (src >> 0) & 0xFF ;
}

void CNXDNProtocol::set_layer3_dstid(uint16_t dst)
{
	m_layer3[5U] = (dst >> 8) & 0xFF;
	m_layer3[6U] = (dst >> 0) & 0xFF ;
}

void CNXDNProtocol::set_layer3_grp(bool grp)
{
	m_layer3[2U] |= grp ? 0x20U : 0x20U;
}

void CNXDNProtocol::set_layer3_blks(uint8_t b)
{
	m_layer3[8U] &= 0xF0U;
	m_layer3[8U] |= b & 0x0FU;
}

void CNXDNProtocol::layer3_encode(uint8_t* d, uint8_t len, uint8_t offset)
{
	for (uint32_t i = 0U; i < len; i++, offset++) {
		bool b = READ_BIT(m_layer3, offset);
		WRITE_BIT(d, i, b);
	}
}

void CNXDNProtocol::encode_crc6(uint8_t *d, uint8_t len)
{
	uint8_t crc = 0x3FU;

	for (uint32_t i = 0U; i < len; i++) {
		bool bit1 = READ_BIT(d, i) != 0x00U;
		bool bit2 = (crc & 0x20U) == 0x20U;
		crc <<= 1;

		if (bit1 ^ bit2)
			crc ^= 0x27U;
	}
	crc &= 0x3FU;
	uint8_t n = len;
	for (uint8_t i = 2U; i < 8U; i++, n++) {
		bool b = READ_BIT((&crc), i);
		WRITE_BIT(d, n, b);
	}
}
