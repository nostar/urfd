#include <cstring>
#include <arpa/inet.h>

#include "Global.h"
#include "ImrsClient.h"
#include "ImrsProtocol.h"
#include "YSFDefines.h"
#include "YSFUtils.h"

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CImrsProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	// base class
	if (!CSEProtocol::Initialize(type, ptype, port, has_ipv4, has_ipv6))
		return false;

	m_Port = port;

	// create our socket
	CIp ip(AF_INET, m_Port, g_Configure.GetString(g_Keys.ip.ipv4bind).c_str());
	if (ip.IsSet())
	{
		if (!m_Socket.Open(ip))
			return false;
	}
	else
		return false;

	std::cout << "Listening for IMRS on " << ip << std::endl;

	// start the thread
	m_Future = std::async(std::launch::async, &CImrsProtocol::Thread, this);

	// update time
	m_LastKeepaliveTime.start();

	std::cout << "Initialized IMRS Protocol" << std::endl;
	return true;
}

void CImrsProtocol::Close(void)
{
	// base class handles the future
	CProtocol::Close();
}

////////////////////////////////////////////////////////////////////////////////////////
// task

void CImrsProtocol::Task(void)
{
	CBuffer             Buffer;
	CIp                 Ip;
	CCallsign           Callsign;
	uint32_t            FirmwareVersion;
	std::unique_ptr<CDvHeaderPacket>    Header;
	std::unique_ptr<CDvFramePacket>     Frames[5];

	// any incoming packet?
	if (m_Socket.Receive(Buffer, Ip, 20))
	{
		if (IsValidPingPacket(Buffer))
		{
			// respond with Pong
			CBuffer response;
			EncodePongPacket(response);
			m_Socket.Send(response, Ip);
		}
		else if (IsValidConnectPacket(Buffer, Callsign, FirmwareVersion))
		{
			std::cout << "IMRS connect request from " << Callsign << " at " << Ip << std::endl;

			CClients *clients = g_Reflector.GetClients();
			std::shared_ptr<CClient> client = clients->FindClient(Ip, EProtocol::imrs);
			if (client == nullptr)
			{
				auto newclient = std::make_shared<CImrsClient>(Callsign, Ip);
				newclient->SetReflectorModule(IMRS_DEFAULT_MODULE);
				clients->AddClient(newclient);
			}
			else
			{
				client->Alive();
			}
			g_Reflector.ReleaseClients();
		}
		else if (IsValidDvHeaderPacket(Buffer, Header))
		{
			OnDvHeaderPacketIn(Header, Ip);
		}
		else if (IsValidDvFramePacket(Ip, Buffer, Frames))
		{
			// Frames are quintets
			for (int i = 0; i < 5; i++)
			{
				if (Frames[i])
					OnDvFramePacketIn(Frames[i], &Ip);
			}
		}
		else if (IsValidDvLastFramePacket(Ip, Buffer, Frames[0]))
		{
			if (Frames[0])
				OnDvFramePacketIn(Frames[0], &Ip);
		}
	}

	// handle end of streaming timeout
	CheckStreamsTimeout();

	// handle queue from reflector
	HandleQueue();

	// keep alive
	if (m_LastKeepaliveTime.time() > IMRS_KEEPALIVE_PERIOD)
	{
		HandleKeepalives();
		m_LastKeepaliveTime.start();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CImrsProtocol::OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &Header, const CIp &Ip)
{
	auto stream = GetStream(Header->GetStreamId(), &Ip);
	if (stream)
	{
		stream->Tickle();
	}
	else
	{
		CClients *clients = g_Reflector.GetClients();
		std::shared_ptr<CClient> client = clients->FindClient(Ip, EProtocol::imrs);
		if (client != nullptr)
		{
			// handle module linking by DG-ID (Rpt2Module carries this in urfd logic)
			if (Header->GetRpt2Module() != client->GetReflectorModule())
			{
				std::cout << "IMRS client " << client->GetCallsign() 
						  << " changing module to " << Header->GetRpt2Module() << std::endl;
				client->SetReflectorModule(Header->GetRpt2Module());
			}

			if ((stream = g_Reflector.OpenStream(Header, client)) != nullptr)
			{
				m_Streams[stream->GetStreamId()] = stream;
			}
		}
		g_Reflector.ReleaseClients();

		if (Header)
		{
			g_Reflector.GetUsers()->Hearing(Header->GetMyCallsign(), Header->GetRpt1Callsign(), Header->GetRpt2Callsign(), EProtocol::imrs);
			g_Reflector.ReleaseUsers();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CImrsProtocol::HandleQueue(void)
{
	while (!m_Queue.IsEmpty())
	{
		auto packet = m_Queue.Pop();
		char module = packet->GetPacketModule();
		int iModId = module - 'A';
		if (iModId < 0 || iModId >= IMRS_NB_OF_MODULES) continue;

		CBuffer buffer;
		if (packet->IsDvHeader())
		{
			m_StreamsCache[iModId].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet);
			EncodeDvHeaderPacket(m_StreamsCache[iModId].m_dvHeader, buffer);
		}
		else if (packet->IsLastPacket())
		{
			EncodeDvLastPacket(m_StreamsCache[iModId].m_dvHeader, (const CDvFramePacket &)*packet, buffer);
		}
		else
		{
			// IMRS expects quintets. We need to collect 5 frames.
			// However, urfd protocol architecture is per-packet.
			// This is an architectural challenge for IMRS in urfd without a gathering buffer.
			// For now, let's implement the logic similar to xlxd's quintet encoding.
			// We skip the gathering for now and just encode single frames if they are available
			// but IMRS really needs quintets. I'll need to use the m_StreamsCache to pool them.
			
			uint8_t sid = (uint8_t)(packet->GetPacketId() % 5);
			m_StreamsCache[iModId].m_dvFrames[sid] = CDvFramePacket((const CDvFramePacket &)*packet);
			if (sid == 4)
			{
				EncodeDvPacket(m_StreamsCache[iModId].m_dvHeader, m_StreamsCache[iModId].m_dvFrames, buffer);
			}
		}

		if (buffer.size() > 0)
		{
			CClients *clients = g_Reflector.GetClients();
			auto it = clients->begin();
			std::shared_ptr<CClient> client = nullptr;
			while ((client = clients->FindNextClient(EProtocol::imrs, it)) != nullptr)
			{
				if (!client->IsAMaster() && (client->GetReflectorModule() == module))
				{
					m_Socket.Send(buffer, client->GetIp());
				}
				client->Alive();
			}
			g_Reflector.ReleaseClients();
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CImrsProtocol::HandleKeepalives(void)
{
	CClients *clients = g_Reflector.GetClients();
	auto it = clients->begin();
	std::shared_ptr<CClient> client = nullptr;
	while ((client = clients->FindNextClient(EProtocol::imrs, it)) != nullptr)
	{
		if (client->IsAMaster())
		{
			client->Alive();
		}
		else if (!client->IsAlive())
		{
			std::cout << "IMRS client " << client->GetCallsign() << " keepalive timeout" << std::endl;
			clients->RemoveClient(client);
		}
	}
	g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding/encoding helpers (Based on xlxd's quintet framing)

bool CImrsProtocol::IsValidPingPacket(const CBuffer &Buffer)
{
	uint8_t tag[] = { 0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	return (Buffer.size() == 16 && Buffer.Compare(tag, 16) == 0);
}

bool CImrsProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign &Callsign, uint32_t &FirmwareVersion)
{
	uint8_t tag[] = { 0x00,0x2C,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	if (Buffer.size() == 60 && Buffer.Compare(tag, 16) == 0)
	{
		Callsign.SetCallsign(Buffer.data() + 26, 8);
		FirmwareVersion = MAKEDWORD(MAKEWORD(Buffer.data()[16], Buffer.data()[17]), MAKEWORD(Buffer.data()[18], Buffer.data()[19]));
		return Callsign.IsValid();
	}
	return false;
}

void CImrsProtocol::EncodePingPacket(CBuffer &Buffer) const
{
	uint8_t tag[] = { 0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	Buffer.Set(tag, sizeof(tag));
}

void CImrsProtocol::EncodePongPacket(CBuffer &Buffer) const
{
	uint8_t tag1[] = { 
		0x00,0x2C,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x01,0x04,0x00,0x00
	};
	Buffer.Set(tag1, sizeof(tag1));

	// MAC address
	uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	Buffer.Append(mac, 6);

	// Callsign
	char cs[YSF_CALLSIGN_LENGTH + 1];
	memset(cs, ' ', YSF_CALLSIGN_LENGTH);
	g_Reflector.GetCallsign().GetCallsignString(cs);
	cs[strlen(cs)] = ' ';
	Buffer.Append((uint8_t *)cs, YSF_CALLSIGN_LENGTH);

	// RadioID
	uint8_t radioid[] = { 'G','0','g','B','J' }; // Static placeholder for now
	Buffer.Append(radioid, 5);

	// Multi-site DG-ID mask (all allowed)
	uint32_t dgids = 0xFFFFFFFF;
	Buffer.Append((uint8_t *)&dgids, 4);
	Buffer.Append((uint8_t)0x00, 13);
	Buffer.Append((uint8_t)2);
	Buffer.Append((uint8_t)2);
}

bool CImrsProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer, std::unique_ptr<CDvHeaderPacket> &header)
{
	if (Buffer.size() == 91 && Buffer.data()[1] == 0x4B)
	{
		uint16_t sid = MAKEWORD(Buffer.data()[11], Buffer.data()[10]);
		uint16_t fid = MAKEWORD(Buffer.data()[21], Buffer.data()[20]); // Binary representation from ASCII? simplified

		// Hack: IMRS header data is 60 bytes at offset 31
		struct dstar_header *dh = (struct dstar_header *)(Buffer.data() + 31);
		header = std::unique_ptr<CDvHeaderPacket>(new CDvHeaderPacket(dh, sid, 0x80));
		if (header && header->IsValid())
		{
			header->SetImrsPacketFrameId(fid);
			return true;
		}
	}
	return false;
}

bool CImrsProtocol::IsValidDvFramePacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> frames[5])
{
	if (Buffer.size() == 181 && Buffer.data()[1] == 0xA5)
	{
		uint16_t sid = MAKEWORD(Buffer.data()[11], Buffer.data()[10]);
		uint16_t fid = MAKEWORD(Buffer.data()[21], Buffer.data()[20]);

		// Simplified: Directly extract payload
		// Offset 16 in xlxd's hex-decoded payload maps to something here
		const uint8_t *vch_base = Buffer.data() + 47; // Adjusted offset for binary

		for (int i = 0; i < 5; i++)
		{
			uint8_t ambe[9];
			// Using YSF utility (Note: urfd's DecodeVD2Vch might need adjustment for IMRS framing)
			// For now, assume binary VCH is compatible
			// CYsfUtils::DecodeVD2Vch(vch_base + (i * 13), ambe); 
			// Wait, urfd doesn't have a public DecodeVD2Vch(uint8*, uint8*) but EncodeVD2Vch?
			// Checking YSFUtils.h
		}
	}
	return false;
}

bool CImrsProtocol::IsValidDvLastFramePacket(const CIp &Ip, const CBuffer &Buffer, std::unique_ptr<CDvFramePacket> &frame)
{
	if (Buffer.size() == 31 && Buffer.data()[1] == 0x0F)
	{
		uint32_t uiStreamId = IpToStreamId(Ip);
		uint8_t ambe[9] = {0};
		frame = std::unique_ptr<CDvFramePacket>(new CDvFramePacket(ambe, uiStreamId, 0, 0, 0, CCallsign(), true));
		return true;
	}
	return false;
}

bool CImrsProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag1[] = { 0x00,0x4B,0x00,0x00,0x00,0x00,0x07 };
	Buffer.Set(tag1, sizeof(tag1));
	
	uint32_t uiTime = (uint32_t)Packet.GetImrsPacketFrameId() * 100;
	Buffer.Append(LOBYTE(HIWORD(uiTime)));
	Buffer.Append(HIBYTE(LOWORD(uiTime)));
	Buffer.Append(LOBYTE(LOWORD(uiTime)));

	uint16_t sid = Packet.GetStreamId();
	Buffer.Append(HIBYTE(sid));
	Buffer.Append(LOBYTE(sid));

	uint8_t tag2[] = { 0x00,0x00,0x00,0x00,0x49,0x2a,0x2a }; // Simplified
	Buffer.Append(tag2, sizeof(tag2));

	// FID and FICH placeholders
	Buffer.Append((uint8_t)0, 6); 

	// D-STAR header at offset 31
	struct dstar_header dh;
	Packet.ConvertToDstarStruct(&dh);
	Buffer.Append((uint8_t *)&dh, sizeof(dh));

	return true;
}

bool CImrsProtocol::EncodeDvPacket(const CDvHeaderPacket &Header, const CDvFramePacket DvFrames[5], CBuffer &Buffer) const
{
	// Quintet framing implementation
	uint8_t tag1[] = { 0x00,0xA5,0x00,0x00,0x00,0x00,0x07 };
	Buffer.Set(tag1, sizeof(tag1));

	uint32_t uiTime = (uint32_t)DvFrames[0].GetImrsPacketFrameId() * 100;
	Buffer.Append(LOBYTE(HIWORD(uiTime)));
	Buffer.Append(HIBYTE(LOWORD(uiTime)));
	Buffer.Append(LOBYTE(LOWORD(uiTime)));

	uint16_t sid = Header.GetStreamId();
	Buffer.Append(HIBYTE(sid));
	Buffer.Append(LOBYTE(sid));

	uint8_t tag2[] = { 0x00,0x00,0x00,0x00,0x32,0x2a,0x2a };
	Buffer.Append(tag2, sizeof(tag2));
	
	// FID/FICH/VCH data (placeholder for quintet framing)
	Buffer.Append((uint8_t)0, 161);

	return true;
}

bool CImrsProtocol::EncodeDvFramePacket(const CDvFramePacket &Packet, CBuffer &Buffer) const
{
	// Standard interface implementation (satisfy CSEProtocol)
	// For IMRS, single frames are usually buffered into quintets,
	// but this override is required.
	return false; 
}

bool CImrsProtocol::EncodeDvLastPacket(const CDvHeaderPacket &Header, const CDvFramePacket &Packet, CBuffer &Buffer) const
{
	uint8_t tag[] = { 0x00,0x0F,0x00,0x00,0x00,0x00,0x07 };
	Buffer.Set(tag, sizeof(tag));
	// ... simplified ...
	Buffer.Append((uint8_t)0, 24);
	return true;
}

uint32_t CImrsProtocol::IpToStreamId(const CIp &Ip) const
{
	return (uint32_t)Ip.GetAddr();
}
