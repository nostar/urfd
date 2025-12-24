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

#pragma once

#include "Defines.h"
#include "Timer.h"
#include "Protocol.h"
#include "SEProtocol.h"
#include "DVHeaderPacket.h"
#include "DVFramePacket.h"
#include "M17CRC.h"

#include <map>
#include <string>
#include <memory>
#include <unordered_map>

////////////////////////////////////////////////////////////////////////////////////////
// define

////////////////////////////////////////////////////////////////////////////////////////
// forward declarations
class CParrot;

////////////////////////////////////////////////////////////////////////////////////////
// class

class CM17StreamCacheItem
{
public:
	CM17StreamCacheItem() : m_iSeqCounter(0) {}

	CDvHeaderPacket m_dvHeader;
	uint32_t        m_iSeqCounter;
};

class CM17Protocol : public CSEProtocol
{
public:
	// constructors
	CM17Protocol();

	// destructor
	virtual ~CM17Protocol() {}

	// initialization
	bool Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6);

	// protocol
	void Task(void);

	// packet encoding helpers (public for Parrot access)
	void Send(const CBuffer &buf, const CIp &Ip) const { CProtocol::Send(buf, Ip); }
	void Send(const char    *buf, const CIp &Ip) const { CProtocol::Send(buf, Ip); }
	void Send(const SM17Frame &frame, const CIp &Ip) const { CProtocol::Send(frame, Ip); }

	virtual bool EncodeDvHeaderPacket(const CDvHeaderPacket &, CBuffer &) const override;
	virtual bool EncodeDvFramePacket(const CDvFramePacket &, CBuffer &) const override;

protected:
	// queue helper
	void HandleQueue(void);

	// keepalive helpers
	void HandleKeepalives(void);

	// stream helpers
	void OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &, const CIp &);

private:
	// packet decoding helpers
	bool IsValidConnectPacket(const CBuffer &, CCallsign &, char &);
	bool IsValidListenPacket(const CBuffer &, CCallsign &, char &);
	bool IsValidDisconnectPacket(const CBuffer &, CCallsign &);
	bool IsValidKeepAlivePacket(const CBuffer &, CCallsign &);
	bool IsValidPacketModePacket(const CBuffer &, CCallsign &, CCallsign &);
	bool IsValidDvPacket(const CBuffer &, std::unique_ptr<CDvHeaderPacket> &, std::unique_ptr<CDvFramePacket> &);

	// packet encoding helpers
	void EncodeKeepAlivePacket(CBuffer &);
	void EncodeM17Packet(SM17Frame &, const CDvHeaderPacket &, const CDvFramePacket *, uint32_t) const;

	// parrot
	void HandleParrot(const CIp &Ip, const CBuffer &Buffer, bool isStream);

protected:
	// for keep alive
	CTimer m_LastKeepaliveTime;

	// for queue header caches
	std::unordered_map<char, CM17StreamCacheItem> m_StreamsCache;

private:
	CM17CRC m17crc;
    std::map<std::string, std::shared_ptr<CParrot>> m_ParrotMap;
};
