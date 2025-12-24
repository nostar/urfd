#pragma once

#include <vector>
#include <cstdint>
#include <atomic>
#include <future>
#include <memory>

#include "Callsign.h"
#include "Timer.h"
#include "M17Client.h"
#include "M17Packet.h"

enum class EParrotState { record, play, done };

class CM17Protocol;

class CParrot
{
public:
	CParrot(const CCallsign &src_addr, std::shared_ptr<CM17Client> spc, uint16_t ft, CM17Protocol *proto) 
        : m_src(src_addr), m_client(spc), m_frameType(ft), m_state(EParrotState::record), m_proto(proto) {}
	virtual ~CParrot() { Quit(); }
	virtual void Add(const CBuffer &Buffer, uint16_t streamId, uint16_t frameNumber) = 0;
	virtual void AddPacket(const CBuffer &Buffer) = 0;
	virtual bool IsExpired() const = 0;
	virtual void Play() = 0;
	virtual bool IsStream() const = 0;
	EParrotState GetState() const { return m_state; }
	const CCallsign &GetSRC() const { return m_src; }
	void Quit() { if (m_fut.valid()) m_fut.get(); }

protected:
	const CCallsign m_src;
	std::shared_ptr<CM17Client> m_client;
	const uint16_t m_frameType;
	std::atomic<EParrotState> m_state;
	std::future<void> m_fut;
	CM17Protocol *m_proto;
};

class CM17StreamParrot : public CParrot
{
public:
	CM17StreamParrot(const CCallsign &src_addr, std::shared_ptr<CM17Client> spc, uint16_t ft, CM17Protocol *proto);
	void Add(const CBuffer &Buffer, uint16_t streamId, uint16_t frameNumber) override;
	void AddPacket(const CBuffer &Buffer) override { (void)Buffer; }
	void Play() override;
	bool IsExpired() const override;
	bool IsStream() const override { return true; }

private:
	void playThread();

	std::vector<std::vector<uint8_t>> m_data;
	bool m_is3200;
	CTimer m_lastHeard;
	uint16_t m_streamId;
};

class CM17PacketParrot : public CParrot
{
public:
	CM17PacketParrot(const CCallsign &src_addr, std::shared_ptr<CM17Client> spc, uint16_t ft, CM17Protocol *proto);
	void Add(const CBuffer &Buffer, uint16_t streamId, uint16_t frameNumber) override { (void)Buffer; (void)streamId; (void)frameNumber; }
	void AddPacket(const CBuffer &Buffer) override;
	void Play() override;
	bool IsExpired() const override { return false; }
	bool IsStream() const override { return false; }

private:
	void playThread();

	CBuffer m_packet;
};
