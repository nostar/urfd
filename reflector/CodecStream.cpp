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
#include "DVFramePacket.h"
#include "PacketStream.h"
#include "CodecStream.h"
#include "Reflector.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor

CCodecStream::CCodecStream(CPacketStream *PacketStream, char module) : m_CSModule(module), m_IsOpen(false)
{
	m_PacketStream = PacketStream;
}

////////////////////////////////////////////////////////////////////////////////////////
// destructor

CCodecStream::~CCodecStream()
{
	// kill the thread
	keep_running = false;
	if ( m_Future.valid() )
	{
		m_Future.get();
	}
	// and close the socket
}

void CCodecStream::ResetStats(uint16_t streamid, ECodecType type)
{
	m_IsOpen = true;
	keep_running = true;
	m_uiStreamId = streamid;
	m_uiPid = 0;
	m_eCodecIn = type;
	m_RTMin = -1;
	m_RTMax = -1;
	m_RTSum = 0;
	m_RTCount = 0;
	m_uiTotalPackets = 0;
	
	// clear any stale packets in the local queue
	while (!m_LocalQueue.IsEmpty())
	{
		m_LocalQueue.Pop();
	}
}

void CCodecStream::ReportStats()
{
	m_IsOpen = false;
	// display stats
	if (m_RTCount > 0)
	{
		double min = 1000.0 * m_RTMin;
		double max = 1000.0 * m_RTMax;
		double ave = 1000.0 * m_RTSum / double(m_RTCount);
		auto prec = std::cout.precision();
		std::cout.precision(1);
		std::cout << std::fixed << "TC round-trip time(ms): " << min << '/' << ave << '/' << max << ", " << m_RTCount << " total packets" << std::endl;
		std::cout.precision(prec);
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// initialization

bool CCodecStream::InitCodecStream()
{
	keep_running = true;
	try
	{
		m_Future = std::async(std::launch::async, &CCodecStream::Thread, this);
	}
	catch(const std::exception& e)
	{
		std::cerr << "Could not start Codec processing on module '" << m_CSModule << "': " << e.what() << std::endl;
		return true;
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////
// thread

void CCodecStream::Thread()
{
	while (keep_running)
	{
		Task();
	}
}

void CCodecStream::Task(void)
{
	STCPacket pack;
	if (g_TCServer.Receive(m_CSModule, &pack, 8))
	{
		if ( m_LocalQueue.IsEmpty() )
		{
			std::cout << "Unexpected transcoded packet received from transcoder: Module='" << pack.module << "' StreamID=" << std::hex << std::showbase << ntohs(pack.streamid) << std::endl;
		}
		else if (m_IsOpen)
		{
			// pop the original packet
			auto Packet = m_LocalQueue.Pop();

			// make sure this is the correct packet
			if ((pack.streamid == Packet->GetCodecPacket()->streamid) && (pack.sequence == Packet->GetCodecPacket()->sequence))
			{

				// update statistics
				auto rt =Packet->m_rtTimer.time();	// the round-trip time
				if (0 == m_RTCount)
				{
					m_RTMin = rt;
					m_RTMax = rt;
				}
				else
				{
					if (rt < m_RTMin)
						m_RTMin = rt;
					else if (rt > m_RTMax)
						m_RTMax = rt;
				}
				m_RTSum += rt;
				m_RTCount++;

				// update content with transcoded data
				Packet->SetCodecData(&pack);
				// mark the DStar sync frames if the source isn't dstar
				if (ECodecType::dstar!=Packet->GetCodecIn() && 0==Packet->GetPacketId()%21)
				{
					const uint8_t DStarSync[] = { 0x55, 0x2D, 0x16 };
					Packet->SetDvData(DStarSync);
				}

				// and push it back to client
				m_PacketStream->ReturnPacket(std::move(Packet));
			}
			else
			{
				// Not the correct packet! It will be ignored
				// Report it
				if (pack.streamid != Packet->GetCodecPacket()->streamid)
					std::cerr << std::hex  << std::showbase << "StreamID mismatch: this voice frame=" << ntohs(Packet->GetCodecPacket()->streamid) << " returned transcoder packet=" << ntohs(pack.streamid) << std::dec << std::noshowbase << std::endl;
				if (pack.sequence != Packet->GetCodecPacket()->sequence)
					std::cerr << "Sequence mismatch: this voice frame=" << Packet->GetCodecPacket()->sequence << " returned transcoder packet=" << pack.sequence << std::endl;
			}
		}
		else
		{
			// Likewise, this packet will be ignored
			std::cout << "Transcoder packet received but CodecStream[" << m_CSModule << "] is closed: Module='" << pack.module << "' StreamID=" << std::hex << std::showbase << ntohs(pack.streamid) << std::endl;
		}
	}

	// anything in our queue, then get it to the transcoder!
	while (! m_Queue.IsEmpty())
	{
		auto &Frame = m_Queue.Front();

		if (m_IsOpen)
		{
			// update important stuff in Frame->m_TCPack for the transcoder
			// sets the packet counter, stream id, last_packet, module and start the trip timer
			Frame->SetTCParams(m_uiTotalPackets++);

			// now send to transcoder
			int fd = g_TCServer.GetFD(Frame->GetCodecPacket()->module);
			if (fd < 0)
			{
				// Crap! We've lost connection to the transcoder!
				// we'll try to fix this on the next pass
				return;
			}

			Frame->m_rtTimer.start();	// start the round-trip timer
			if (g_TCServer.Send(Frame->GetCodecPacket()))
			{
				// ditto, we'll try to fix this on the next pass
				return;
			}
			// the fd was good and then the send was successful, so...
			// push the frame to our local queue where it can wait for the transcoder


			m_LocalQueue.Push(std::move(m_Queue.Pop()));
		}
	}
}
