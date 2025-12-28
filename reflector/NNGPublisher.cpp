#include "NNGPublisher.h"
#include "Global.h"
#include <iostream>
#include <sstream>

CNNGPublisher::CNNGPublisher()
    : m_started(false)
{
    m_sock.id = 0;
}

CNNGPublisher::~CNNGPublisher()
{
    Stop();
}

bool CNNGPublisher::Start(const std::string &addr)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_started) return true;

    int rv;
    if ((rv = nng_pub0_open(&m_sock)) != 0) {
        std::cerr << "NNG: Failed to open pub socket: " << nng_strerror(rv) << std::endl;
        return false;
    }

    if ((rv = nng_listen(m_sock, addr.c_str(), nullptr, 0)) != 0) {
        std::cerr << "NNG: Failed to listen on " << addr << ": " << nng_strerror(rv) << std::endl;
        nng_close(m_sock);
        return false;
    }

    m_started = true;
    std::cout << "NNG: Publisher started at " << addr << std::endl;
    return true;
}

void CNNGPublisher::Stop()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_started) return;

    nng_close(m_sock);
    m_started = false;
    std::cout << "NNG: Publisher stopped" << std::endl;
}

void CNNGPublisher::Publish(const nlohmann::json &event)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_started) return;

    if (m_sock.id == 0) {
        std::cerr << "NNG debug: Cannot publish, socket not initialized." << std::endl;
        return;
    }
    std::string msg = event.dump();
    if (g_Configure.GetBoolean(g_Keys.dashboard.debug))
        std::cout << "NNG debug: Attempting to publish message of size " << msg.size() << ": " << msg << std::endl;
    int rv = nng_send(m_sock, (void *)msg.c_str(), msg.size(), NNG_FLAG_NONBLOCK);
    if (rv == 0) {
        // Count event instead of logging
        std::string type = event["type"];
        m_EventCounts[type]++;
    } else if (rv != NNG_EAGAIN) {
        std::cerr << "NNG: Send error: " << nng_strerror(rv) << std::endl;
    }
}

std::string CNNGPublisher::GetAndClearStats()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_EventCounts.empty()) return "";

    std::stringstream ss;
    bool first = true;
    for (const auto& kv : m_EventCounts)
    {
        if (!first) ss << ", ";
        ss << "\"" << kv.first << "\": " << kv.second;
        first = false;
    }
    m_EventCounts.clear();
    return ss.str();
}
