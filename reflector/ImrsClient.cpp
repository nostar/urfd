#include "ImrsClient.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructors

CImrsClient::CImrsClient()
{
}

CImrsClient::CImrsClient(const CCallsign &callsign, const CIp &ip, char reflectorModule)
	: CClient(callsign, ip, reflectorModule)
{
}

CImrsClient::CImrsClient(const CImrsClient &client)
	: CClient(client)
{
}

////////////////////////////////////////////////////////////////////////////////////////
// status

bool CImrsClient::IsAlive(void) const
{
	return (m_LastKeepaliveTime.time() < IMRS_KEEPALIVE_TIMEOUT);
}
