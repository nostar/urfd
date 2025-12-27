#include <iostream>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <sstream>

#include "TCSocket.h"

CTCSocket::CTCSocket() : m_Running(false), m_Connected(false)
{
	m_Sock.id = 0;
}

CTCSocket::~CTCSocket()
{
	Close();
}

void CTCSocket::Close()
{
	m_Running = false;
	if (m_Thread.joinable())
		m_Thread.join();

	if (m_Sock.id != 0)
	{
		nng_close(m_Sock);
		m_Sock.id = 0;
	}
	m_Connected = false;
}

void CTCSocket::Close(char module)
{
	// In multiplexed mode, we cannot close a single module's connection independently
	// without closing the whole pipe. So this is a no-op or full close.
	// For now, no-op to allow other modules to survive transient errors.
	// std::cerr << "Close(" << module << ") ignored in NNG mode" << std::endl;
}

bool CTCSocket::Send(const STCPacket *packet)
{
	if (m_Sock.id == 0) return true;

	int rv = nng_send(m_Sock, (void*)packet, sizeof(STCPacket), 0);
	if (rv != 0)
	{
		// std::cerr << "NNG Send Error: " << nng_strerror(rv) << std::endl;
		return true;
	}
	return false;
}

bool CTCSocket::IsConnected(char module) const
{
	return m_Connected;
}

int CTCSocket::GetFD(char module) const
{
	// Legacy helper for checking connection state
	// CodecStream expects < 0 on failure
	return m_Connected ? 1 : -1;
}

void CTCSocket::Dispatcher()
{
	while (m_Running)
	{
		STCPacket *buf = nullptr;
		size_t sz = 0;
		// 100ms timeout to check m_Running
		int rv = nng_recv(m_Sock, &buf, &sz, NNG_FLAG_ALLOC); 
		
		if (rv == 0)
		{
			if (sz == sizeof(STCPacket))
			{
				STCPacket pkt;
				memcpy(&pkt, buf, sizeof(STCPacket));
				nng_free(buf, sz);

				if (m_ClientQueue)
				{
					// Client mode: everything goes to one queue
					m_ClientQueue->Push(pkt);
				}
				else
				{
					// Server mode: route by module
					auto it = m_Queues.find(pkt.module);
					if (it != m_Queues.end())
					{
						it->second->Push(pkt);
					}
					else
					{
						// Unknown module or not configured?
						// In urfd, we might want to auto-create logic or drop?
						// For now drop, as configured modules are set in Open
					}
				}
			}
			else
			{
				nng_free(buf, sz);
				std::cerr << "Received packet of incorrect size: " << sz << std::endl;
			}
		}
		else if (rv != NNG_ETIMEDOUT)
		{
			// Fatal error? 
			// std::cerr << "NNG Recv Error: " << nng_strerror(rv) << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}

// ---------------- SERVER ----------------

// ---------------- SERVER ----------------

bool CTCServer::Open(const std::string &address, const std::string &modules, uint16_t port)
{
	m_Modules = modules;
	// Initialize queues for configured modules
	for (char c : m_Modules)
	{
		m_Queues[c] = std::make_shared<CTCPacketQueue>();
	}

	int rv;
	if ((rv = nng_pair1_open(&m_Sock)) != 0)
	{
		std::cerr << "nng_pair1_open failed: " << nng_strerror(rv) << std::endl;
		return true;
	}

	// Set receive timeout to 100ms for dispatcher loop
	nng_duration timeout = 100;
	nng_socket_set_ms(m_Sock, NNG_OPT_RECVTIMEO, timeout);

	std::stringstream url;
	if (address.find("ipc://") == 0) {
		url << address;
	} else if (address.find("/") == 0 || address.find("./") == 0 || address.find("../") == 0) {
		url << "ipc://" << address;
	} else {
		url << "tcp://" << address << ":" << port;
	}

	if ((rv = nng_listen(m_Sock, url.str().c_str(), nullptr, 0)) != 0)
	{
		std::cerr << "nng_listen failed: " << nng_strerror(rv) << " URL: " << url.str() << std::endl;
		return true;
	}

	m_Running = true;
	m_Connected = true;
	m_Thread = std::thread([this] { Dispatcher(); });

	return false;
}

bool CTCServer::Receive(char module, STCPacket *packet, int ms)
{
	auto it = m_Queues.find(module);
	if (it == m_Queues.end()) return false;

	return it->second->Pop(*packet, ms);
}

bool CTCServer::AnyAreClosed() const
{
	// If the dispatcher is running, we assume open.
	// NNG handles reconnections.
	return !m_Running;
}

bool CTCServer::Accept()
{
	// No manual accept needed with NNG
	return false;
}


// ---------------- CLIENT ----------------

bool CTCClient::Open(const std::string &address, const std::string &modules, uint16_t port)
{
	m_Modules = modules;
	m_ClientQueue = std::make_shared<CTCPacketQueue>();

	int rv;
	if ((rv = nng_pair1_open(&m_Sock)) != 0)
	{
		std::cerr << "nng_pair1_open failed: " << nng_strerror(rv) << std::endl;
		return true;
	}

	// Set receive timeout for dispatcher
	nng_duration timeout = 100;
	nng_socket_set_ms(m_Sock, NNG_OPT_RECVTIMEO, timeout);

	std::stringstream url;
	if (address.find("ipc://") == 0) {
		url << address;
	} else if (address.find("/") == 0 || address.find("./") == 0 || address.find("../") == 0) {
		url << "ipc://" << address;
	} else {
		url << "tcp://" << address << ":" << port;
	}

	// Client dials asynchronously so it can retry in background
	if ((rv = nng_dial(m_Sock, url.str().c_str(), nullptr, NNG_FLAG_NONBLOCK)) != 0)
	{
		std::cerr << "nng_dial failed: " << nng_strerror(rv) << " URL: " << url.str() << std::endl;
		return true;
	}

	m_Running = true;
	m_Connected = true;
	m_Thread = std::thread([this] { Dispatcher(); });

    // Give it a moment to connect? Not strictly necessary.
    
	return false;
}

void CTCClient::Receive(std::queue<std::unique_ptr<STCPacket>> &queue, int ms)
{
    // Wait up to ms for the first packet
    STCPacket p;
    if (m_ClientQueue->Pop(p, ms))
    {
        queue.push(std::make_unique<STCPacket>(p));
        // Drain the rest without waiting
        while (m_ClientQueue->Pop(p, 0))
        {
             queue.push(std::make_unique<STCPacket>(p));
        }
    }
}

void CTCClient::ReConnect()
{
	// NNG handles reconnection automatically
}
