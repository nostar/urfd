#pragma once

#include <string>
#include <cstdint>
#include <mutex>
#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <condition_variable>
#include <map>
#include <atomic>
#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>

#include "TCPacketDef.h"

// Specialized thread-safe queue for STCPacket by value, avoiding template conflict
class CTCPacketQueue {
    std::queue<STCPacket> q;
    std::mutex m;
    std::condition_variable cv;
public:
    void Push(const STCPacket& p) {
        std::lock_guard<std::mutex> l(m);
        q.push(p);
        cv.notify_one();
    }
    bool Pop(STCPacket& p, int ms) {
        std::unique_lock<std::mutex> l(m);
        // Wait up to ms if queue is empty
        if (q.empty()) {
            if (ms <= 0) return false;
            // wait_for returns false if timeout, true if predicate is true
            if (!cv.wait_for(l, std::chrono::milliseconds(ms), [this]{ return !q.empty(); })) {
                return false; // timeout
            }
        }
        
        p = q.front();
        q.pop();
        return true;
    }
};

class CTCSocket
{
public:
	CTCSocket();
	virtual ~CTCSocket();

	virtual bool Open(const std::string &address, const std::string &modules, uint16_t port) = 0;
	void Close(); 
	void Close(char module); 

	bool Send(const STCPacket *packet);

	bool IsConnected(char module) const;
    int GetFD(char module) const; // Legacy compat: returns 1 if connected, -1 if not

protected:
    nng_socket m_Sock;
    std::thread m_Thread;
    std::atomic<bool> m_Running;
    std::atomic<bool> m_Connected;
	std::string m_Modules;

    // Per-module input queues
    std::map<char, std::shared_ptr<CTCPacketQueue>> m_Queues;
    // Client queue (receives all)
    std::shared_ptr<CTCPacketQueue> m_ClientQueue;

    void Dispatcher();
};

class CTCServer : public CTCSocket
{
public:
	CTCServer() : CTCSocket() {}
	~CTCServer() {}
	bool Open(const std::string &address, const std::string &modules, uint16_t port);
	bool Receive(char module, STCPacket *packet, int ms);
	bool AnyAreClosed() const;
	bool Accept(); // Checks NNG state
};

class CTCClient : public CTCSocket
{
public:
	CTCClient() : CTCSocket() {}
	~CTCClient() {}
	bool Open(const std::string &address, const std::string &modules, uint16_t port);
	void Receive(std::queue<std::unique_ptr<STCPacket>> &queue, int ms);
	void ReConnect(); // No-op in NNG
};
