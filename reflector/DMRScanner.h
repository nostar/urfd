/*
 *   Copyright (c) 2024 by Thomas A. Early N7TAE
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#pragma once

#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <ctime>
#include <sstream>

#include "Timer.h"

// Structure to hold subscription details
struct SSubscription {
	unsigned int tgid;
	unsigned int timeout; // seconds, 0 = infinite
	std::time_t expiry;   // absolute time
    bool isStatic;        // true if static (no timeout)
};

class CDMRScanner
{
public:
	CDMRScanner();
	virtual ~CDMRScanner();

	// Configuration
	void Configure(bool singleMode, unsigned int defaultTimeout, unsigned int holdTime);
    bool IsSingleMode() const { return m_SingleMode; }

	// Subscription Management
	void UpdateSubscriptions(const std::string& options);
	void AddSubscription(unsigned int tgid, int timeslot, unsigned int timeout, bool isStatic = false);
    void RenewSubscription(unsigned int tgid, int timeslot, unsigned int timeout);
	void RemoveSubscription(unsigned int tgid, int timeslot);
	void ClearSubscriptions();
	bool IsSubscribed(unsigned int tgid) const;
	bool IsSubscribed(unsigned int tgid, int timeslot) const;

	// Packet Access Check (Scanner Logic)
	// Returns true if packet with this TG should be processed
	bool CheckAccess(unsigned int tgid, int slot = 0);

	// Getters
	unsigned int GetFirstSubscription() const;
	unsigned int GetSubscriptionSlot(unsigned int tgid) const;
    std::vector<SSubscription> GetSubscriptions(int slot) const;
	void GetActiveTalkgroups(std::vector<unsigned int>& tgs) const;
	unsigned int GetCurrentScanTG(int slot) const { return (slot >= 1 && slot <= 2) ? m_CurrentScanTG[slot-1] : 0; }

private:
	mutable std::recursive_mutex m_Mutex;

	// Config
	bool m_SingleMode;
	unsigned int m_DefaultTimeout;
	unsigned int m_HoldTime;

	// State
	std::map<int, std::vector<SSubscription>> m_Subscriptions; // Map Timeslot -> List of Subscriptions
	// Scanner State per slot [0]=TS1, [1]=TS2
	unsigned int m_CurrentScanTG[2];
	CTimer m_HoldTimer[2];

	// Helpers
	void cleanupExpired();
    void parseOptions(const std::string& options);
};
