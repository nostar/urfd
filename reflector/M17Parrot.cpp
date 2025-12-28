#include <thread>
#include <chrono>

#include "M17Parrot.h"
#include "Global.h"
#include "M17Protocol.h"

////////////////////////////////////////////////////////////////////////////////////////
// Stream Parrot

CM17StreamParrot::CM17StreamParrot(const CCallsign &src_addr, std::shared_ptr<CM17Client> spc, uint16_t ft, CM17Protocol *proto)
	: CParrot(src_addr, spc, ft, proto), m_streamId(0)
{
	m_is3200 = (0x4U == (0x4U & ft));
	m_lastHeard.start();
}

void CM17StreamParrot::Add(const CBuffer &Buffer, uint16_t streamId, uint16_t frameNumber)
{
	(void)frameNumber; // We generate our own sequence on playback
	if (m_data.size() < 500u)
	{
		m_streamId = streamId;
		size_t length = m_is3200 ? 16 : 8;

        bool isStandard = false;
        if (Buffer.size() == 56) isStandard = true;
        
        // Use parser to get payload pointer safely
        CM17Packet parser(Buffer.data(), isStandard);
        const uint8_t *payload = parser.GetPayload();
        
        m_data.emplace_back(payload, payload + length);
	}
	m_lastHeard.start();
}

void CM17StreamParrot::Play()
{
	m_fut = std::async(std::launch::async, &CM17StreamParrot::playThread, this);
}

bool CM17StreamParrot::IsExpired() const
{
	return m_lastHeard.time() > 1.6; // 1.6s timeout like mrefd
}

void CM17StreamParrot::playThread()
{
	m_state = EParrotState::play;
	
    // Determine format to send
    bool useLegacy = g_Configure.GetBoolean(g_Keys.m17.compat); 
    
    uint8_t buffer[60];
    CM17Packet pkt(buffer, !useLegacy);
    memset(buffer, 0, 60); // clear buffer
    
    pkt.SetMagic();
    pkt.SetStreamId(m_streamId);
    
    // I will add `SetDestBytes` to CM17Packet? Or just use explicit CCallsign.
    // I will try to use the `m_src` as dest? No, that's what `CodeOut` does.
    // I will use `pkt.SetDestCallsign` with a dummy, and then manually overwrite if needed?
    // Better: `CM17Packet` exposes `GetLichPointer()`. I can write to it manually!
    
    // Set Source
    pkt.SetSourceCallsign(m_src);
    pkt.SetFrameType(m_frameType);

    // Set Dest to FF
    uint8_t *lich = pkt.GetLICHPointer();
    memset(lich, 0xFF, 6); // Dest is at offset 0 of LICH

	auto clock = std::chrono::steady_clock::now();
	size_t size = m_data.size();
    
	for (size_t n = 0; n < size; n++)
	{
		size_t length = m_is3200 ? 16 : 8;
        pkt.SetPayload(m_data[n].data());
        
        uint16_t fn = (uint16_t)n;
		if (n == size - 1)
			fn |= 0x8000u;
        pkt.SetFrameNumber(fn);
        
        // CRC
        CM17CRC m17crc_inst;
        if (!useLegacy) {
            // Standard LICH CRC
             uint16_t l_crc = m17crc_inst.CalcCRC(lich, 28);
            ((SM17LichStandard*)lich)->crc = htons(l_crc);
        }
        
        uint16_t p_crc = m17crc_inst.CalcCRC(pkt.GetBuffer(), pkt.GetSize()-2);
		pkt.SetCRC(p_crc);

		clock = clock + std::chrono::milliseconds(40);
		std::this_thread::sleep_until(clock);
        
        if (m_proto) {
            CBuffer sendBuf;
            sendBuf.Append(pkt.GetBuffer(), pkt.GetSize());
            m_proto->Send(sendBuf, m_client->GetIp());
        }
		m_data[n].clear();
	}
	m_data.clear();
	m_state = EParrotState::done;
}

////////////////////////////////////////////////////////////////////////////////////////
// Packet Parrot

CM17PacketParrot::CM17PacketParrot(const CCallsign &src_addr, std::shared_ptr<CM17Client> spc, uint16_t ft, CM17Protocol *proto)
	: CParrot(src_addr, spc, ft, proto)
{
}

void CM17PacketParrot::AddPacket(const CBuffer &Buffer)
{
    m_packet = Buffer;
}

void CM17PacketParrot::Play()
{
	m_fut = std::async(std::launch::async, &CM17PacketParrot::playThread, this);
}

void CM17PacketParrot::playThread()
{
	m_state = EParrotState::play;
    
    // 100ms delay like mrefd
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Change destination to ALL (broadcast back to sender) or specific?
    // M17P is usually 4 magic + 6 dst + 6 src + ...
    if (m_packet.size() >= 10)
    {
        memset(m_packet.data() + 4, 0xFF, 6); // Set dst to @ALL
        
        // Recalculate CRC
        CM17CRC m17crc;
        // M17P packets also have a CRC at the end. 
        // CRC is usually last 2 bytes.
        size_t len = m_packet.size();
        if (len >= 2)
        {
            uint16_t crc = htons(m17crc.CalcCRC(m_packet.data(), len - 2));
            memcpy(m_packet.data() + len - 2, &crc, 2);
        }
        
        if (m_proto)
            m_proto->Send(m_packet, m_client->GetIp());
    }
    
	m_state = EParrotState::done;
}
