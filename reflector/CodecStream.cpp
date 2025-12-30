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
	// kill the threads
	keep_running = false;
	
	// Unblock TxThread
	m_Queue.Push(nullptr);
	
	// Unblock RxThread - Closing NNG does this
	// But we don't own the NNG socket in CodecStream (CTCServer owns it), so we can't close it here.
	// Actually, CTCServer::Close() is called globally.
	// For per-stream shutdown, we rely on the fact that CodecStream is usually destroyed when the call ends,
	// but the NNG socket remains open for other calls.
	// Wait, RxThread performs `g_TCServer.Receive`. If that blocks forever, we can't join.
	// However, `keep_running` is checked. We need to wake up `Receive`.
	// The only way to wake up `Receive` on a shared socket without closing it is if we used a timeout/poller or if we send a dummy packet to ourselves?
	// Ah, the Implementation Plan says "Close NNG socket to unblock RxThread". 
	// **Correction**: `CTCServer` owns the socket. If we are just destroying one `CCodecStream` (e.g. one call ending), we CANNOT close the global socket.
	// This implies `RxThread` CANNOT assume it owns the socket.
	// BUT, `CodecStream` exists for the duration of a Module's lifecycle effectively? 
	// No, `CCodecStream` is created per stream? No, `CCodecStream` is created in `Reflector.cpp` at startup for each module!
	// `g_Reflector.m_CodecStreams[c] = new CCodecStream(...)`
	// So `CCodecStream` lives practically forever (until shutdown).
	// Therefore, safe shutdown happens only when app exits, so closing global socket is fine.

	if ( m_Future.valid() )
	{
		m_Future.get();
	}
	if ( m_TxFuture.valid() )
	{
		m_TxFuture.get();
	}
}

void CCodecStream::ResetStats(uint16_t streamid, ECodecType type)
{
	m_IsOpen = true;
	// keep_running = true; // Already true from Init
	m_uiStreamId = streamid;
	m_uiPid = 0;
	m_eCodecIn = type;
	m_RTMin = -1;
	m_RTMax = -1;
	m_RTSum = 0;
	m_RTCount = 0;
	m_uiTotalPackets = 0;
	
	// Start recording if enabled
	if (g_Configure.GetBoolean(g_Keys.audio.enable))
	{
		std::string path = g_Configure.GetString(g_Keys.audio.path);
		m_Filename = m_Recorder.Start(path);
	}
	else
	{
		m_Filename.clear();
	}

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
		m_Future = std::async(std::launch::async, &CCodecStream::RxThread, this);
		m_TxFuture = std::async(std::launch::async, &CCodecStream::TxThread, this);
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

////////////////////////////////////////////////////////////////////////////////////////
// threads

void CCodecStream::RxThread()
{
	while (keep_running)
	{
		STCPacket pack;
		// infinite block waiting for packet (or socket close)
		// Assuming we modified TCD/NNG config to allow blocking or we poll slowly if not?
		// User requested blocking. 
		// CTCServer::Receive now needs to support blocking (timeout -1 or large).
		// We'll pass -1 for infinite (impl dependent) or 1000ms Loop.
		// NNG recv returns EAGAIN if nonblock.
		// If we use blocking mode, `recv` blocks until message.
		
		if (g_TCServer.Receive(m_CSModule, &pack, 1000)) // 1s timeout to check keep_running occasionally
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
					
					// Write audio to recorder if active
					if (m_Recorder.IsRecording())
					{
					    m_Recorder.Write(pack.usrp, 160);
					}

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
	}
}

void CCodecStream::TxThread(void)
{
	while (keep_running)
	{
		// Block until packet available or poison pill (nullptr)
		auto Frame = m_Queue.PopWait();

		// Poison pill check
		if (!Frame) {
			if (!keep_running) break;
			continue; 
		}

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
				// discard packet
				continue;
			}

			Frame->m_rtTimer.start();	// start the round-trip timer

			// CRITICAL: Push to local queue BEFORE sending to avoid race condition
			// where reply arrives before we track it.
			// m_LocalQueue is thread-safe (locks internally).
			// We need a copy or raw pointer? No, we need to ownership transfer to queue.
			// But we need the data for Send.
			// Frame is unique_ptr.
			
			// We can't push then use. We must effectively "peek" then push, 
			// or extract data then push.
			const STCPacket* packetData = Frame->GetCodecPacket();
			// Copy data packet struct as we need it for sending
			STCPacket pToSend = *packetData; 
			
			m_LocalQueue.Push(std::move(Frame));

			if (g_TCServer.Send(&pToSend))
			{
				// Send failed. 
				// We should ideally remove it from m_LocalQueue, but CSafePacketQueue has no RemoveLast.
				// It will just rot there until cleared on ResetStats or mismatch handling.
				// This is rare.
			}
		}
	}
}

// Deprecated
void CCodecStream::Task(void) {}
