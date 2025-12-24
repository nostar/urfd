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
		// Payload is at offset 40 in SM17Frame (4 magic + 2 streamid + 28 lich + 2 fn + 16 payload + 2 crc)
        // urfd's CDvFramePacket/CM17Packet probably maps this.
        // For simplicity in this implementation, we assume Buffer passed is the raw payload OR mapped.
        // Looking at M17Protocol.cpp:410, payload starts at packet.payload
        
        const uint8_t *payload = Buffer.data() + 40; // payload offset in SM17Frame
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
	
    SM17Frame frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(frame.magic, "M17 ", 4);
    frame.streamid = m_streamId; // reuse or generate new? mrefd generates new.
    
    // Set LICH addresses
    memset(frame.lich.addr_dst, 0xFF, 6); // @ALL
    m_src.CodeOut(frame.lich.addr_src);
    frame.lich.frametype = htons(m_frameType);

	auto clock = std::chrono::steady_clock::now();
	size_t size = m_data.size();
    
	for (size_t n = 0; n < size; n++)
	{
		size_t length = m_is3200 ? 16 : 8;
        memcpy(frame.payload, m_data[n].data(), length);
        
        uint16_t fn = (uint16_t)n;
		if (n == size - 1)
			fn |= 0x8000u;
        frame.framenumber = htons(fn);
        
        CM17CRC m17crc;
		frame.crc = htons(m17crc.CalcCRC((uint8_t*)&frame, sizeof(SM17Frame)-2));

		clock = clock + std::chrono::milliseconds(40);
		std::this_thread::sleep_until(clock);
        
        if (m_proto)
            m_proto->Send(frame, m_client->GetIp());
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
