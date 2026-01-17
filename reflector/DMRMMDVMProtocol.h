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

#pragma once

#include "Defines.h"
#include "Timer.h"
#include "Protocol.h"
#include "DVHeaderPacket.h"
#include "DVFramePacket.h"

////////////////////////////////////////////////////////////////////////////////////////
// define

// frame type
#define DMRMMDVM_FRAMETYPE_VOICE     0
#define DMRMMDVM_FRAMETYPE_VOICESYNC 1
#define DMRMMDVM_FRAMETYPE_DATASYNC  2

// slot type
#define MMDVM_SLOTTYPE_HEADER        1
#define MMDVM_SLOTTYPE_TERMINATOR    2

// DMRMMDVM Module ID
#define MMDVM_MODULE_ID             'B'

////////////////////////////////////////////////////////////////////////////////////////
// class

class CDmrmmdvmStreamCacheItem
{
public:
	CDvHeaderPacket m_dvHeader;
	CDvFramePacket  m_dvFrame0;
	CDvFramePacket  m_dvFrame1;

	uint8_t  m_uiSeqId;
};


class CDmrmmdvmProtocol : public CProtocol
{
public:
	// initialization
	bool Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6);

	// task
	void Task(void);

protected:
	// queue helper
	void HandleQueue(void);

	// keepalive helpers
	void HandleKeepalives(void);

	// stream helpers
	void OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &, const CIp &, uint8_t, uint8_t, uint8_t);

	// packet decoding helpers
	bool IsValidConnectPacket(const CBuffer &, CCallsign *, const CIp &);
	bool IsValidAuthenticationPacket(const CBuffer &, CCallsign *, const CIp &);
	bool IsValidDisconnectPacket(const CBuffer &, CCallsign *);
	bool IsValidConfigPacket(const CBuffer &, CCallsign *, const CIp &);
	bool IsValidOptionPacket(const CBuffer &, CCallsign *, const CIp &);
	bool IsValidKeepAlivePacket(const CBuffer &, CCallsign *);
	bool IsValidRssiPacket(const CBuffer &, CCallsign *, int *);
	bool IsValidDvHeaderPacket(const CBuffer &, std::unique_ptr<CDvHeaderPacket> &, uint8_t *, uint8_t *, uint8_t *);
	bool IsValidDvFramePacket(const CIp &, const CBuffer &, std::unique_ptr<CDvHeaderPacket> &, std::array<std::unique_ptr<CDvFramePacket>, 3> &);
	bool IsValidDvLastFramePacket(const CBuffer &, std::unique_ptr<CDvFramePacket> &);

	// packet encoding helpers
	void EncodeKeepAlivePacket(CBuffer *, std::shared_ptr<CClient>);
	void EncodeAckPacket(CBuffer *, const CCallsign &);
	void EncodeConnectAckPacket(CBuffer *, const CCallsign &, uint32_t);
	void EncodeNackPacket(CBuffer *, const CCallsign &);
	void EncodeClosePacket(CBuffer *, std::shared_ptr<CClient>);
	bool EncodeMMDVMHeaderPacket(const CDvHeaderPacket &, uint8_t, uint32_t, uint8_t, CBuffer *) const;
	void EncodeMMDVMPacket(const CDvHeaderPacket &, const CDvFramePacket &, const CDvFramePacket &, const CDvFramePacket &, uint8_t, uint32_t, uint8_t, CBuffer *) const;
	void EncodeLastMMDVMPacket(const CDvHeaderPacket &, uint8_t, uint32_t, uint8_t, CBuffer *) const;

	// dmr DstId to Module helper
	char DmrDstIdToModule(uint32_t) const;
	uint32_t ModuleToDmrDestId(char) const;

	// Buffer & LC helpers
	void AppendVoiceLCToBuffer(CBuffer *, uint32_t, uint32_t) const;
	void AppendTerminatorLCToBuffer(CBuffer *, uint32_t, uint32_t) const;
	void ReplaceEMBInBuffer(CBuffer *, uint8_t) const;
	void AppendDmrIdToBuffer(CBuffer *, uint32_t) const;
	void AppendDmrRptrIdToBuffer(CBuffer *, uint32_t) const;


protected:
	// for keep alive
	 CTimer         m_LastKeepaliveTime;

	// for stream id
	uint16_t              m_uiStreamId;

	// for queue header caches
	std::unordered_map<char, CDmrmmdvmStreamCacheItem> m_StreamsCache;

	// for authentication
	uint32_t              m_uiAuthSeed;

    // for debug logging
    int                   m_debugFrameCount;

	// config data
	unsigned m_DefaultId;
};
