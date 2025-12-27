#pragma once

#include <string>
#include <mutex>
#include <nlohmann/json.hpp>
#include <map>
#include <nng/nng.h>
#include <nng/protocol/pubsub0/pub.h>

class CNNGPublisher
{
public:
    CNNGPublisher();
    ~CNNGPublisher();

    bool Start(const std::string &addr);
    void Stop();

    void Publish(const nlohmann::json &event);

    std::string GetAndClearStats();

private:
    nng_socket m_sock;
    std::mutex m_mutex;
    bool m_started;
    
    // Event counters
    std::map<std::string, int> m_EventCounts;
};
