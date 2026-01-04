/*
 *   Copyright (c) 2024 by Thomas A. Early N7TAE
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "DMRScanner.h"
#include <iostream>
#include <algorithm>

CDMRScanner::CDMRScanner() :
	m_SingleMode(false),
	m_DefaultTimeout(600),
	m_HoldTime(5)
{
    m_CurrentScanTG[0] = 0;
    m_CurrentScanTG[1] = 0;
}

CDMRScanner::~CDMRScanner()
{
}

void CDMRScanner::Configure(bool singleMode, unsigned int defaultTimeout, unsigned int holdTime)
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
	m_SingleMode = singleMode;
	m_DefaultTimeout = defaultTimeout;
	m_HoldTime = holdTime;
}

void CDMRScanner::UpdateSubscriptions(const std::string& options)
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    parseOptions(options);
}

void CDMRScanner::parseOptions(const std::string& options)
{
    // Basic parsing: Options: TS1=4001,4002;TS2=9;AUTO=600
    // Split by ';'
    if (options.empty()) return;

    std::stringstream ss(options);
    std::string segment;
    unsigned int timeout = m_DefaultTimeout;
    
    // First pass to find AUTO/Timeout if present (to apply to TGs)
    // Actually, typically AUTO applies to all in the string.
    // Let's parse into a temporary structure first.
    
    std::vector<unsigned int> ts1_tgs;
    std::vector<unsigned int> ts2_tgs;
    
    while(std::getline(ss, segment, ';'))
    {
        size_t eq = segment.find('=');
        if (eq != std::string::npos)
        {
            std::string key = segment.substr(0, eq);
            std::string val = segment.substr(eq + 1);
            
            // trim key/val
            key.erase(0, key.find_first_not_of(" \t\r\n"));
            key.erase(key.find_last_not_of(" \t\r\n") + 1);
            
            if (key == "Options") {
                // Recursive parse or just assume val contains the options?
                // Example: Options=TS1=4001,4002
                // Wait, typically MMDVMHost sends: Options=TS1=4001,4002;TS2=9
                // If the entire string is "Options=...", we need to parse 'val'.
                // If 'val' contains semicolons, std::getline logic above might have split it already?
                // No, std::getline splits on ';' first.
                // Case 1: "Options=TS1=4001,4002;TS2=9"
                // Segment 1: "Options=TS1=4001,4002". Key="Options", Val="TS1=4001,4002".
                // We should parse 'Val'.
                // But wait, 'Val' is "TS1=4001,4002". It'looks like a K=V itself?
                // Let's recursively call parseOptions(val) or just process val.
                // But verify val format.
                // Simplest: Check if val starts with TS1/TS2/AUTO ?
                parseOptions(val); 
            }
            else if (key == "AUTO") {
                try {
                    timeout = std::stoul(val);
                } catch(...) {}
            } else if (key == "TS1") {
                std::stringstream vs(val);
                std::string v;
                while(std::getline(vs, v, ',')) {
                    try { ts1_tgs.push_back(std::stoul(v)); } catch(...) {}
                }
            } else if (key == "TS2") {
                std::stringstream vs(val);
                std::string v;
                while(std::getline(vs, v, ',')) {
                    try { ts2_tgs.push_back(std::stoul(v)); } catch(...) {}
                }
            }
        }
    }
    
    // Apply (Replace existing usually? Or append? The prompt said "Options string... to configure subscriptions". 
    // Usually RPTC is a full state update. Let's assume replace for provided timeslots).
    // Actually user said "clients can send options... similar to freedmr". 
    // Freedmr options usually add/set. 
    // Let's implement ADD logic, but if SingleMode is on, it naturally replaces.
    // Wait, typical "Options=" in password means "Set these". So we should probably existing ones if they are re-specified?
    // Let's assume for now we ADD/UPDATE. 
    
    // Actually, simpler implementation for now: Just Add.
    // parseOptions: call AddSubscription with isStatic=true
    for (auto tg : ts1_tgs) AddSubscription(tg, 1, timeout, true);
    for (auto tg : ts2_tgs) AddSubscription(tg, 2, timeout, true);
}

void CDMRScanner::AddSubscription(unsigned int tgid, int timeslot, unsigned int timeout, bool isStatic)
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    
    if (tgid == 4000) {
        m_Subscriptions[timeslot].clear();
        return;
    }

	if (m_SingleMode) {
		m_Subscriptions[timeslot].clear();
        isStatic = true; // Single Mode always static
	}

	// Remove if exists to update
	RemoveSubscription(tgid, timeslot);

	SSubscription sub;
	sub.tgid = tgid;
	sub.timeout = timeout;
	sub.expiry = (timeout == 0) ? 0 : std::time(nullptr) + timeout;
    sub.isStatic = isStatic;

	m_Subscriptions[timeslot].push_back(sub);
}

void CDMRScanner::RenewSubscription(unsigned int tgid, int timeslot, unsigned int timeout)
{
    std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    
    if (m_Subscriptions.count(timeslot)) {
        for (auto& s : m_Subscriptions.at(timeslot)) {
            if (s.tgid == tgid && !s.isStatic) {
                s.expiry = (timeout == 0) ? 0 : std::time(nullptr) + timeout;
                return;
            }
        }
    }
}

void CDMRScanner::RemoveSubscription(unsigned int tgid, int timeslot)
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
	auto& subs = m_Subscriptions[timeslot];
	subs.erase(std::remove_if(subs.begin(), subs.end(),
		[tgid](const SSubscription& s) { return s.tgid == tgid; }), subs.end());
}

void CDMRScanner::ClearSubscriptions()
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
	m_Subscriptions.clear();
	m_CurrentScanTG[0] = 0;
    m_CurrentScanTG[1] = 0;
}

bool CDMRScanner::IsSubscribed(unsigned int tgid) const
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    std::time_t now = std::time(nullptr);

	for (const auto& pair : m_Subscriptions) {
		for (const auto& sub : pair.second) {
			if (sub.tgid == tgid) {
			    if (!sub.isStatic && sub.timeout > 0 && now > sub.expiry) continue;
				return true;
			}
		}
	}
	return false;
}

bool CDMRScanner::IsSubscribed(unsigned int tgid, int timeslot) const
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    std::time_t now = std::time(nullptr);
    
    if (m_Subscriptions.count(timeslot)) {
        for (const auto& sub : m_Subscriptions.at(timeslot)) {
            if (sub.tgid == tgid) {
			    if (!sub.isStatic && sub.timeout > 0 && now > sub.expiry) continue;
				return true;
            }
        }
    }
    return false;
}

bool CDMRScanner::CheckAccess(unsigned int tgid, int slot)
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);

    if (slot == 0) {
        // Check both slots
        return CheckAccess(tgid, 1) || CheckAccess(tgid, 2);
    }

    if (slot < 1 || slot > 2) return false;
    int idx = slot - 1;

	cleanupExpired();

	if (!IsSubscribed(tgid, slot)) return false;

	// Scanner Logic for Slot
	if (m_CurrentScanTG[idx] != 0) {
		if (m_CurrentScanTG[idx] == tgid) {
			m_HoldTimer[idx].start();
			return true;
		}

		if (m_HoldTimer[idx].time() < m_HoldTime) {
			return false;
		}
	}

	m_CurrentScanTG[idx] = tgid;
	m_HoldTimer[idx].start();
	return true;
}

void CDMRScanner::cleanupExpired()
{
	std::time_t now = std::time(nullptr);
	for (auto& pair : m_Subscriptions) {
		auto& subs = pair.second;
		subs.erase(std::remove_if(subs.begin(), subs.end(),
			[now](const SSubscription& s) { return !s.isStatic && s.timeout > 0 && now > s.expiry; }), subs.end());
	}
    
    if (m_CurrentScanTG[0] != 0 && !IsSubscribed(m_CurrentScanTG[0], 1)) m_CurrentScanTG[0] = 0;
    if (m_CurrentScanTG[1] != 0 && !IsSubscribed(m_CurrentScanTG[1], 2)) m_CurrentScanTG[1] = 0;
}

unsigned int CDMRScanner::GetFirstSubscription() const
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    
    // Check TS2 first (Standard DMRReflector usually)
    if (m_Subscriptions.count(2) && !m_Subscriptions.at(2).empty()) return m_Subscriptions.at(2).front().tgid;
    if (m_Subscriptions.count(1) && !m_Subscriptions.at(1).empty()) return m_Subscriptions.at(1).front().tgid;
    
    // Check any
    for(const auto& p : m_Subscriptions) {
        if (!p.second.empty()) return p.second.front().tgid;
    }
    return 0;
}

unsigned int CDMRScanner::GetSubscriptionSlot(unsigned int tgid) const
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    
    // Check TS1
    if (m_Subscriptions.count(1)) {
        for(const auto& s : m_Subscriptions.at(1)) {
            if (s.tgid == tgid) return 1;
        }
    }
    // Check TS2
    if (m_Subscriptions.count(2)) {
        for(const auto& s : m_Subscriptions.at(2)) {
            if (s.tgid == tgid) return 2;
        }
    }
    return 0;
}

std::vector<SSubscription> CDMRScanner::GetSubscriptions(int slot) const
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    if (m_Subscriptions.count(slot)) {
        return m_Subscriptions.at(slot);
    }
    return {};
}

void CDMRScanner::GetActiveTalkgroups(std::vector<unsigned int>& tgs) const
{
	std::lock_guard<std::recursive_mutex> lock(m_Mutex);
    tgs.clear();
    
    std::time_t now = std::time(nullptr);
    
    // Check TS1
    if (m_Subscriptions.count(1)) {
        for(const auto& s : m_Subscriptions.at(1)) {
            if (!s.isStatic && s.timeout > 0 && now > s.expiry) continue;
            tgs.push_back(s.tgid);
        }
    }
    // Check TS2
    if (m_Subscriptions.count(2)) {
        for(const auto& s : m_Subscriptions.at(2)) {
            if (!s.isStatic && s.timeout > 0 && now > s.expiry) continue;
            tgs.push_back(s.tgid);
        }
    }
}
