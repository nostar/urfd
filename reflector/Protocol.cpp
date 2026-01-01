//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.

// urfd -- The universal reflector
// Copyright © 2021 Thomas A. Early N7TAE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <iostream>
#include <map>
#include <ctime>
#include <iomanip>
#include "Defines.h"
#include "Global.h"
#include "Protocol.h"
#include "Clients.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor


CProtocol::CProtocol() : keep_running(true) {}


////////////////////////////////////////////////////////////////////////////////////////
// destructor

CProtocol::~CProtocol()
{
	// kill threads
	Close();

	// empty queue
	while ( !m_Queue.IsEmpty() )
	{
		m_Queue.Pop();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// initialization

bool CProtocol::Initialize(const char *type, const EProtocol ptype, const uint16_t port, const bool has_ipv4, const bool has_ipv6)
{
	m_Port = port;
	// init reflector apparent callsign
	m_ReflectorCallsign = g_Reflector.GetCallsign();

	// reset stop flag
	keep_running = true;

	// update the reflector callsign
	if (type)
		m_ReflectorCallsign.PatchCallsign(0, type, 3);

	// create our sockets
	if (has_ipv4)
	{
		const std::string ipv4binding(g_Configure.GetString(g_Keys.ip.ipv4bind));
		CIp ip4(AF_INET, port, ipv4binding.c_str());
		if ( ip4.IsSet() )
		{
			if (! m_Socket4.Open(ip4))
				return false;
		}
		std::cout << "Listening on " << ip4 << std::endl;
	}

	if (g_Configure.IsString(g_Keys.ip.ipv6bind))
	{
		if (has_ipv6)
		{
			const std::string ipv6binding(g_Configure.GetString(g_Keys.ip.ipv6bind));
			CIp ip6(AF_INET6, port, ipv6binding.c_str());
			if ( ip6.IsSet() )
			{
				if (! m_Socket6.Open(ip6))
				{
					m_Socket4.Close();
					return false;
				}
				std::cout << "Listening on " << ip6 << std::endl;
			}
		}
	}

	try
	{
		m_Future = std::async(std::launch::async, &CProtocol::Thread, this);
	}
	catch (const std::exception &e)
	{
		std::cerr << "Could not start protocol on port " << port << ": " << e.what() << std::endl;
		m_Socket4.Close();
		m_Socket6.Close();
		return false;
	}

	return true;
}

void CProtocol::Thread()
{
	while (keep_running)
	{
		Task();
	}
}

void CProtocol::Close(void)
{
	keep_running = false;
	if ( m_Future.valid() )
	{
		m_Future.get();
	}
	m_Socket4.Close();
	m_Socket6.Close();
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

void CProtocol::OnDvFramePacketIn(std::unique_ptr<CDvFramePacket> &Frame, const CIp *Ip)
{
	// find the stream
	auto stream = GetStream(Frame->GetStreamId(), Ip);
	if ( stream )
	{
		// set the packet module, the transcoder needs this
		Frame->SetPacketModule(stream->GetOwnerClient()->GetReflectorModule());
		// and push
		stream->Push(std::move(Frame));
	}
//#ifdef DEBUG
	else
	{
		std::cout << std::showbase << std::hex;
		// Rate limit warnings: only log once every 60 seconds per stream ID
		static std::map<uint16_t, std::time_t> last_warning;
		std::time_t now = std::time(nullptr);
		uint16_t sid = ntohs(Frame->GetStreamId());

		if (last_warning.find(sid) == last_warning.end() || (now - last_warning[sid]) > 60) {
			std::cout << "Orphaned Frame with ID " << std::hex << std::showbase << sid 
                      << std::noshowbase << std::dec << " on " << *Ip 
                      << " (Suppressed for 60s)" << std::endl;
			last_warning[sid] = now;
		}
		Frame.reset();
	}
//#endif
}

////////////////////////////////////////////////////////////////////////////////////////
// stream handle helpers

std::shared_ptr<CPacketStream> CProtocol::GetStream(uint16_t uiStreamId, const CIp *Ip)
{
	auto it = m_Streams.find(uiStreamId);
	if (it == m_Streams.end())
		return nullptr;

	if (Ip != nullptr && it->second->GetOwnerIp() != nullptr)
	{
		if (*Ip == *it->second->GetOwnerIp())
		{
			return it->second;
		}
	}

	return nullptr;
}

void CProtocol::CheckStreamsTimeout(void)
{
	for ( auto it=m_Streams.begin(); it!=m_Streams.end(); )
	{
		// time out ?
		if ( it->second->IsExpired() )
		{
			// yes, close it
			g_Reflector.CloseStream(it->second);
			// and remove it from the m_Streams map
			it = m_Streams.erase(it);
		}
		else
		{
			it++;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// syntax helper

bool CProtocol::IsNumber(char c) const
{
	return ((c >= '0') && (c <= '9'));
}

bool CProtocol::IsLetter(char c) const
{
	return ((c >= 'A') && (c <= 'Z'));
}

bool CProtocol::IsSpace(char c) const
{
	return (c == ' ');
}

////////////////////////////////////////////////////////////////////////////////////////
// DestId to Module helper

char CProtocol::DmrDstIdToModule(uint32_t tg) const
{
	return ((char)((tg % 26)-1) + 'A');
}

uint32_t CProtocol::ModuleToDmrDestId(char m) const
{
	return (uint32_t)(m - 'A')+1;
}

////////////////////////////////////////////////////////////////////////////////////////
// Receivers

bool CProtocol::Receive6(CBuffer &buf, CIp &ip, int time_ms)
{
	return m_Socket6.Receive(buf, ip, time_ms);
}

bool CProtocol::Receive4(CBuffer &buf, CIp &ip, int time_ms)
{
	return m_Socket4.Receive(buf, ip, time_ms);
}

bool CProtocol::ReceiveDS(CBuffer &buf, CIp &ip, int time_ms)
{
	auto fd4 = m_Socket4.GetSocket();
	auto fd6 = m_Socket6.GetSocket();

	if (fd4 < 0)
	{
		if (fd6 < 0)
			return false;
		return m_Socket6.Receive(buf, ip, time_ms);
	}
	else if (fd6 < 0)
		return m_Socket4.Receive(buf, ip, time_ms);

	fd_set fset;
	FD_ZERO(&fset);
	FD_SET(fd4, &fset);
	FD_SET(fd6, &fset);
	int max = (fd4 > fd6) ? fd4 : fd6;
	struct timeval tv;
	tv.tv_sec = time_ms / 1000;
	tv.tv_usec = (time_ms % 1000) * 1000;

	auto rval = select(max+1, &fset, 0, 0, &tv);
	if (rval <= 0)
	{
		if (rval < 0)
			std::cerr << "ReceiveDS select error: " << strerror(errno) << std::endl;
		return false;
	}

	if (FD_ISSET(fd4, &fset))
		return m_Socket4.ReceiveFrom(buf, ip);
	else
		return m_Socket6.ReceiveFrom(buf, ip);
}

////////////////////////////////////////////////////////////////////////////////////////
// dual stack senders

void CProtocol::Send(const CBuffer &buf, const CIp &Ip) const
{
	switch (Ip.GetFamily())
	{
	case AF_INET:
		m_Socket4.Send(buf, Ip);
		break;
	case AF_INET6:
		m_Socket6.Send(buf, Ip);
		break;
	default:
		std::cerr << "Wrong family: " << Ip.GetFamily() << std::endl;
		break;
	}
}

void CProtocol::Send(const char *buf, const CIp &Ip) const
{
	switch (Ip.GetFamily())
	{
	case AF_INET:
		m_Socket4.Send(buf, Ip);
		break;
	case AF_INET6:
		m_Socket6.Send(buf, Ip);
		break;
	default:
		std::cerr << "ERROR: wrong family: " << Ip.GetFamily() << std::endl;
		break;
	}
}

void CProtocol::Send(const CBuffer &buf, const CIp &Ip, uint16_t port) const
{
	switch (Ip.GetFamily())
	{
	case AF_INET:
		m_Socket4.Send(buf, Ip, port);
		break;
	case AF_INET6:
		m_Socket6.Send(buf, Ip, port);
		break;
	default:
		std::cerr << "Wrong family: " << Ip.GetFamily() << " on port " << port << std::endl;
		break;
	}
}

void CProtocol::Send(const char *buf, const CIp &Ip, uint16_t port) const
{
	switch (Ip.GetFamily())
	{
	case AF_INET:
		m_Socket4.Send(buf, Ip, port);
		break;
	case AF_INET6:
		m_Socket6.Send(buf, Ip, port);
		break;
	default:
		std::cerr << "Wrong family: " << Ip.GetFamily() << " on port " << port << std::endl;
		break;
	}
}



#ifdef DEBUG
void CProtocol::Dump(const char *title, const uint8_t *data, int length)
{
	std::cout << title << std::endl;

	unsigned int offset = 0U;

	while (length > 0) {

		unsigned int bytes = (length > 16) ? 16U : length;

		for (unsigned i = 0U; i < bytes; i++) {
			if (i)
				std::cout << " ";
			std::cout << std::hex << std::setw(2) << std::right << std::setfill('0') << int(data[offset + i]);
		}

		for (unsigned int i = bytes; i < 16U; i++)
			std::cout << "   ";

		std::cout << "   *";

		for (unsigned i = 0U; i < bytes; i++) {
			unsigned char c = data[offset + i];

			if (::isprint(c))
				std::cout << c;
			else
				std::cout << '.';
		}

		std::cout << '*' << std::endl;

		offset += 16U;

		if (length >= 16)
			length -= 16;
		else
			length = 0;
	}
}
#endif
