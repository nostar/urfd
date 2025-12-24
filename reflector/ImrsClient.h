#pragma once

#include "Client.h"

////////////////////////////////////////////////////////////////////////////////////////
// class

class CImrsClient : public CClient
{
public:
	// constructors
	CImrsClient();
	CImrsClient(const CCallsign &callsign, const CIp &ip, char reflectorModule = ' ');
	CImrsClient(const CImrsClient &client);

	// status
	virtual bool IsAlive(void) const;
};
