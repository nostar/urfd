#pragma once

#include <string>
#include <array>

#include "Defines.h"
#include "Timer.h"
#include "SEProtocol.h"
#include "DVHeaderPacket.h"
#include "DVFramePacket.h"
#include "UDPMsgSocket.h"

////////////////////////////////////////////////////////////////////////////////////////
// defines

#define IMRS_NB_OF_MODULES 26

////////////////////////////////////////////////////////////////////////////////////////
// classes

class CImrsStreamCacheItem
{
public:
	CImrsStreamCacheItem() {}
	~CImrsStreamCacheItem() {}

	CDvHeaderPacket m_dvHeader;
	CDvFramePacket  m_dvFrames[5];
};

class CImrsProtocol : public CSEProtocol
{
public:
	// constructor
	CImrsProtocol() : m_Port(IMRS_PORT) {}

	// initialization
	bool Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6);

	// close
	void Close(void);

	// task
	void Task(void);

protected:
	// queue helper
	void HandleQueue(void);

	// keepalive helpers
	void HandleKeepalives(void);

	// stream helpers
	void OnDvHeaderPacketIn(std::unique_ptr<CDvHeaderPacket> &, const CIp &);

	// packet decoding helpers
	bool IsValidPingPacket(const CBuffer &);
	bool IsValidConnectPacket(const CBuffer &, CCallsign &, uint32_t &);
	bool IsValidDvHeaderPacket(const CBuffer &, std::unique_ptr<CDvHeaderPacket> &);
	bool IsValidDvFramePacket(const CIp &, const CBuffer &, std::unique_ptr<CDvFramePacket> frames[5]);
	bool IsValidDvLastFramePacket(const CIp &, const CBuffer &, std::unique_ptr<CDvFramePacket> &);

	// packet encoding overrides
	virtual bool EncodeDvHeaderPacket(const CDvHeaderPacket &, CBuffer &) const;
	virtual bool EncodeDvFramePacket(const CDvFramePacket &, CBuffer &) const;

	// IMRS specific encoding
	void EncodePingPacket(CBuffer &) const;
	void EncodePongPacket(CBuffer &) const;
	bool EncodeDvPacket(const CDvHeaderPacket &, const CDvFramePacket DvFrames[5], CBuffer &) const;
	bool EncodeDvLastPacket(const CDvHeaderPacket &, const CDvFramePacket &, CBuffer &) const;

	// helpers
	uint32_t IpToStreamId(const CIp &) const;

protected:
	// time
	CTimer              m_LastKeepaliveTime;

	// sockets
	CUdpSocket          m_Socket;

	// configuration
	uint16_t            m_Port;

	// stream cache for quintet framing
	std::array<CImrsStreamCacheItem, IMRS_NB_OF_MODULES> m_StreamsCache;
};
