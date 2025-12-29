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


#include "PacketStream.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor

CPacketStream::CPacketStream(char module) : m_PSModule(module)
{
	m_bOpen = false;
	m_uiStreamId = 0;
	m_uiPacketCntr = 0;
	m_OwnerClient = nullptr;
	m_CodecStream = nullptr;
}

bool CPacketStream::InitCodecStream()
{
	m_CodecStream = std::unique_ptr<CCodecStream>(new CCodecStream(this, m_PSModule));
	if (m_CodecStream)
		return m_CodecStream->InitCodecStream();
	else
	{
		std::cerr << "Could not create a CCodecStream for module '" << m_PSModule << "'" << std::endl;
		return true;
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// open / close

bool CPacketStream::OpenPacketStream(const CDvHeaderPacket &DvHeader, std::shared_ptr<CClient>client)
{
	// not already open?
	if ( !m_bOpen )
	{
		// update status
		m_bOpen = true;
		m_uiStreamId = DvHeader.GetStreamId();
		m_uiPacketCntr = 0;
		m_DvHeader = DvHeader;
		m_OwnerClient = client;
		m_LastPacketTime.start();
		if (m_CodecStream)
			m_CodecStream->ResetStats(m_uiStreamId, m_DvHeader.GetCodecIn());
		return true;
	}
	return false;
}

void CPacketStream::ClosePacketStream(void)
{
	// update status
	m_bOpen = false;
	m_uiStreamId = 0;
	m_OwnerClient.reset();
	if (m_CodecStream)
		m_CodecStream->ReportStats();
}

////////////////////////////////////////////////////////////////////////////////////////
// push & pop

void CPacketStream::Push(std::unique_ptr<CPacket> Packet)
{
	// update stream dependent packet data
	m_LastPacketTime.start();
	if (Packet->IsDvFrame())
	{
		Packet->UpdatePids(m_uiPacketCntr++);
	}
	// ... Is there a CodecStream (is this module transcoded)?
	// AND Is this voice data?
	// AND Is this from a local client and not from an interlinked URF
	if ( m_CodecStream && Packet->IsDvFrame() && Packet->IsLocalOrigin())
	{
		// yes, push packet to trancoder queue
		// first, recast to a CDvFramePacket
		auto Frame = std::unique_ptr<CDvFramePacket>(static_cast<CDvFramePacket *>(Packet.release()));
		// trancoder will push it to m_Queue after transcoding
		// is completed
		m_CodecStream->Push(std::move(Frame));
	}
	else
	{
		// no, just bypass transcoder
		m_Queue.Push(std::move(Packet));
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// get

const CIp *CPacketStream::GetOwnerIp(void)
{
	if ( m_OwnerClient != nullptr )
	{
		return &(m_OwnerClient->GetIp());
	}
	return nullptr;
}

std::string CPacketStream::StopRecording()
{
	if (m_CodecStream)
		return m_CodecStream->StopRecording();
	return "";
}
