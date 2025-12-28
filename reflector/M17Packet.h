//
//  Copyright © 2020 Thomas A. Early, N7TAE
//
// ----------------------------------------------------------------------------
//
//    m17ref is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    m17ref is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    with this software.  If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <string.h>
#include <memory>

#include "Callsign.h"

////////////////////////////////////////////////////////////////////////////////////////
// aliases

// M17 Packets
//all structures must be big endian on the wire, so you'll want htonl (man byteorder 3) and such.
using SM17LichLegacy = struct __attribute__((__packed__)) lich_tag {
	uint8_t  addr_dst[6];
	uint8_t  addr_src[6];
	uint16_t frametype; //frametype flag field per the M17 spec
	uint8_t  nonce[14]; //bytes for the nonce
}; // 6 + 6 + 2 + 14 = 28 bytes

// Standard LICH includes CRC
using SM17LichStandard = struct __attribute__((__packed__)) lich_std_tag {
	uint8_t  addr_dst[6];
	uint8_t  addr_src[6];
	uint16_t frametype;
	uint8_t  nonce[14];
	uint16_t crc;
}; // 6 + 6 + 2 + 14 + 2 = 30 bytes

//without SYNC or other parts
using SM17FrameLegacy = struct __attribute__((__packed__)) m17_tag {
	uint8_t  magic[4];
	uint16_t streamid;
	SM17LichLegacy lich;
	uint16_t framenumber;
	uint8_t  payload[16];
	uint16_t crc; 	//16 bit CRC
}; // 4 + 2 + 28 + 2 + 16 + 2 = 54 bytes

using SM17FrameStandard = struct __attribute__((__packed__)) m17_std_tag {
	uint8_t  magic[4];
	uint16_t streamid;
	SM17LichStandard lich;
	uint16_t framenumber;
	uint8_t  payload[16];
	uint16_t crc; 	//16 bit CRC
}; // 4 + 2 + 30 + 2 + 16 + 2 = 56 bytes


using SLinkPacket = struct __attribute__((__packed__)) link_tag {
	uint8_t magic[4];
	uint8_t fromcs[6];
	uint8_t mod;
}; // 37 bytes

class CM17Packet
{
public:
	CM17Packet() {}
	CM17Packet(const uint8_t *buf, bool isStandard = false);
	const CCallsign &GetDestCallsign() const;
	const CCallsign &GetSourceCallsign() const;
	char GetDestModule() const;
	uint16_t GetFrameNumber() const;
	uint16_t GetFrameType() const;
	const uint8_t *GetPayload() const;
	const uint8_t *GetNonce() const;
	void SetPayload(const uint8_t *newpayload);
	uint16_t GetStreamId() const;
	uint16_t GetCRC() const;
	void SetCRC(uint16_t crc);
	void SetDestCallsign(const CCallsign &cs);
	void SetSourceCallsign(const CCallsign &cs);
	void SetStreamId(uint16_t id);
	void SetFrameNumber(uint16_t fn);
	void SetFrameType(uint16_t ft);
	void SetNonce(const uint8_t *nonce);
	
	void SetMagic();
	
	uint8_t *GetLICHPointer() { return m_isStandard ? (uint8_t*)&m_frame.standard.lich : (uint8_t*)&m_frame.legacy.lich; }
	size_t GetLICHSize() const { return m_isStandard ? sizeof(SM17LichStandard) : sizeof(SM17LichLegacy); }

	const uint8_t *GetBuffer() const { return m_frame.buffer; }
	size_t GetSize() const { return m_isStandard ? sizeof(SM17FrameStandard) : sizeof(SM17FrameLegacy); }

	bool IsLastPacket() const;

private:
	CCallsign destination, source;
	// Flexible storage for either Legacy or Standard frame
	union {
		SM17FrameLegacy legacy;
		SM17FrameStandard standard;
		uint8_t buffer[60];
	} m_frame;
	bool m_isStandard;
};
