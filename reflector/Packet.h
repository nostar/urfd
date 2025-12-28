#pragma once

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

// Origin Id

#include "Buffer.h"
#include "TCPacketDef.h"
#include "M17Packet.h"

enum class EOrigin : std::uint8_t { local=0, peer=1 };

class CPacket
{
public:
	// constructor
	CPacket();
	CPacket(const CBuffer &Buffer);
	CPacket(uint16_t sid, uint8_t dstarpid);
	CPacket(uint16_t sid, uint8_t dmrpid, uint8_t dmrsubpid, bool lastpacket);
	CPacket(uint16_t sid, uint8_t pid, bool lastpacket);
	CPacket(uint16_t sid, bool isusrp, bool lastpacket);
	CPacket(uint16_t sid, uint8_t ysfpid, uint8_t ysfsubpid, uint8_t ysfsubpidmax, bool lastpacket);
	CPacket(uint16_t sid, uint8_t dstarpid, uint8_t dmrpid, uint8_t dmrsubpid, uint8_t ysfpid, uint8_t ysfsubpid, uint8_t ysfsubpidmax, ECodecType, bool lastpacket);
	CPacket(const CM17Packet &);

	// identity
	virtual std::unique_ptr<CPacket> Copy(void) = 0;
	virtual bool IsDvHeader(void) const = 0;
	virtual bool IsDvFrame(void) const = 0;
	bool IsLastPacket(void) const                { return m_bLastPacket; }

	// get
	virtual bool IsValid(void) const             { return true; }
	uint16_t     GetStreamId(void) const         { return m_uiStreamId; }
	uint16_t     M17FrameNumber(void) const      { return m_uiM17FrameNumber; }
	uint8_t      GetPacketId(void) const         { return m_uiDstarPacketId; }
	uint8_t      GetDstarPacketId(void) const    { return m_uiDstarPacketId; }
	uint8_t      GetDmrPacketId(void) const      { return m_uiDmrPacketId; }
	uint8_t      GetDmrPacketSubid(void) const   { return m_uiDmrPacketSubid; }
	uint8_t      GetYsfPacketId(void) const      { return m_uiYsfPacketId; }
	uint8_t      GetYsfPacketSubId(void) const   { return m_uiYsfPacketSubId; }
	uint8_t      GetYsfPacketFrameId(void) const { return m_uiYsfPacketFrameId; }
	uint8_t      GetImrsPacketId(void) const      { return m_uiImrsPacketId; }
	uint8_t      GetImrsPacketSubId(void) const   { return m_uiImrsPacketSubId; }
	uint8_t      GetImrsPacketFrameId(void) const { return m_uiImrsPacketFrameId; }
	uint8_t      GetNXDNPacketId(void) const     { return m_uiNXDNPacketId; }
	char         GetPacketModule(void) const     { return m_cModule; }
	bool         IsLocalOrigin(void) const       { return (m_eOrigin == EOrigin::local); }
	ECodecType   GetCodecIn(void) const          { return m_eCodecIn; }

	// set
	void UpdatePids(const uint32_t);
	void SetPacketModule(char cMod)    { m_cModule = cMod; }
	void SetLastPacket(bool value)     { m_bLastPacket = value; }
	void SetLocalOrigin(void)          { m_eOrigin = EOrigin::local; }
	void SetRemotePeerOrigin(void)     { m_eOrigin = EOrigin::peer; }
	void SetImrsPacketFrameId(uint8_t id) { m_uiImrsPacketFrameId = id; }
	void SetCodecIn(ECodecType type)   { m_eCodecIn = type; }

protected:
	// network
	void EncodeInterlinkPacket(const char *magic, CBuffer &Buffer) const;
	static constexpr unsigned GetNetworkSize() noexcept
	{
		return 4u + sizeof(ECodecType) + sizeof(EOrigin) + sizeof(bool) + sizeof(char) + sizeof(uint16_t) + sizeof(uint32_t) + 10u * sizeof(uint8_t);
	}

	// data
	// if you change something here, you'll need to update the CBuffer ctor and EncodeInterlinkPacket()!!!
	ECodecType m_eCodecIn;
	EOrigin    m_eOrigin;
	bool       m_bLastPacket;
	char       m_cModule;
	uint16_t   m_uiStreamId;
	uint32_t   m_uiM17FrameNumber;
	uint8_t    m_uiDstarPacketId;
	uint8_t    m_uiDmrPacketId;
	uint8_t    m_uiDmrPacketSubid;
	uint8_t    m_uiYsfPacketId;
	uint8_t    m_uiYsfPacketSubId;
	uint8_t    m_uiYsfPacketFrameId;
	uint8_t    m_uiImrsPacketId;
	uint8_t    m_uiImrsPacketSubId;
	uint8_t    m_uiImrsPacketFrameId;
	uint8_t    m_uiNXDNPacketId;
};
