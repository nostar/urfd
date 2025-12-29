
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

#include <cstdint>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "IP.h"

CIp::CIp() : is_set(false)
{
	Clear();
}

CIp::CIp(const char *address, int family, int type, uint16_t port) : is_set(true)
{
	Clear();
	if (0 == strncasecmp(address, "none", 4))
	{
		is_set = false;
		return;
	}
	struct addrinfo hints, *result;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = family;
	hints.ai_socktype = type;
	if (0 == getaddrinfo(address, (port ? std::to_string(port).c_str() : nullptr), &hints, &result))
	{
		memcpy(&addr, result->ai_addr, result->ai_addrlen);
		addr.ss_family = result->ai_family;
		freeaddrinfo(result);
	}
	SetPort(port);
}
CIp::CIp(const int family, const uint16_t port, const char *address) : is_set(true)
{
	Initialize(family, port, address);
}

void CIp::Initialize(const int family, const uint16_t port, const char *address)
{
	Clear();
	if (0 == strncasecmp(address, "none", 4))
	{
		is_set = false;
		return;
	}
	is_set = true;
	addr.ss_family = family;
	if (AF_INET == family)
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		addr4->sin_port = htons(port);
		if (address)
		{
			if (0 == strncasecmp(address, "loc", 3))
				inet_pton(AF_INET, "127.0.0.1", &(addr4->sin_addr));
			else if (0 == strncasecmp(address, "any", 3))
				inet_pton(AF_INET, "0.0.0.0", &(addr4->sin_addr));
			else
			{
				if (1 > inet_pton(AF_INET, address, &(addr4->sin_addr)))
				{
					std::cerr << "Address Initialization Error: '" << address << "' is not a valdid IPV4 address!" << std::endl;
					is_set = false;
				}
			}
		}
	}
	else if (AF_INET6 == family)
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		addr6->sin6_port = htons(port);
		if (address)
		{
			if (0 == strncasecmp(address, "loc", 3))
				inet_pton(AF_INET6, "::1", &(addr6->sin6_addr));
			else if (0 == strncasecmp(address, "any", 3))
				inet_pton(AF_INET6, "::", &(addr6->sin6_addr));
			else
			{
				if (1 > inet_pton(AF_INET6, address, &(addr6->sin6_addr)))
				{
					std::cerr << "Address Initialization Error: '" << address << "' is not a valid IPV6 address!" << std::endl;
					is_set = false;
				}
			}
		}
	}
	else
	{
		std::cerr << "Error: Wrong address family type:" << family << " for [" << (address ? address : "NULL") << "]:" << port << std::endl;
		is_set = false;
	}
}

bool CIp::operator==(const CIp &rhs) const	// compares ports, addresses and families
{
	// if anything is not equal, then we are done
	if (addr.ss_family != rhs.addr.ss_family)
		return false;
	if (AF_INET == addr.ss_family)
	{
		auto l = (struct sockaddr_in *)&addr;
		auto r = (struct sockaddr_in *)&rhs.addr;
		if (l->sin_addr.s_addr == r->sin_addr.s_addr)
			return l->sin_port == r->sin_port;
		else
			return false;
	}
	else if (AF_INET6 == addr.ss_family)
	{
		auto l = (struct sockaddr_in6 *)&addr;
		auto r = (struct sockaddr_in6 *)&rhs.addr;
		if (0 == memcmp(&(l->sin6_addr), &(r->sin6_addr), sizeof(struct in6_addr)))
			return l->sin6_port == r->sin6_port;
		else
			return false;
	}
	return false;
}

bool CIp::operator!=(const CIp &rhs) const	// compares ports, addresses and families
{
	// if anything is not equal, then we are done
	if (addr.ss_family != rhs.addr.ss_family)
		return true;
	if (AF_INET == addr.ss_family)
	{
		auto l = (struct sockaddr_in *)&addr;
		auto r = (struct sockaddr_in *)&rhs.addr;
		if (l->sin_addr.s_addr != r->sin_addr.s_addr)
			return true;
		else
			return l->sin_port != r->sin_port;
	}
	else if (AF_INET6 == addr.ss_family)
	{
		auto l = (struct sockaddr_in6 *)&addr;
		auto r = (struct sockaddr_in6 *)&rhs.addr;
		if (0 != memcmp(&(l->sin6_addr), &(r->sin6_addr), sizeof(struct in6_addr)))
			return true;
		else
			return l->sin6_port != r->sin6_port;
	}
	return true;
}

bool CIp::operator<(const CIp &rhs) const
{
	if (addr.ss_family != rhs.addr.ss_family)
		return addr.ss_family < rhs.addr.ss_family;
	
    if (AF_INET == addr.ss_family) {
		auto l = (const struct sockaddr_in *)&addr;
		auto r = (const struct sockaddr_in *)&rhs.addr;
        if (l->sin_addr.s_addr != r->sin_addr.s_addr)
            return ntohl(l->sin_addr.s_addr) < ntohl(r->sin_addr.s_addr);
        return ntohs(l->sin_port) < ntohs(r->sin_port);
    } else if (AF_INET6 == addr.ss_family) {
		auto l = (const struct sockaddr_in6 *)&addr;
		auto r = (const struct sockaddr_in6 *)&rhs.addr;
        int cmp = memcmp(&(l->sin6_addr), &(r->sin6_addr), sizeof(struct in6_addr));
        if (cmp != 0) return cmp < 0;
        return ntohs(l->sin6_port) < ntohs(r->sin6_port);
    }
    return false;
}


bool CIp::AddressIsZero() const
{
	if (AF_INET == addr.ss_family)
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		return (addr4->sin_addr.s_addr == 0U);
	}
	else
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		for (unsigned int i=0; i<16; i++)
		{
			if (addr6->sin6_addr.s6_addr[i])
				return false;
		}
		return true;
	}
}

void CIp::ClearAddress()
{
	if (AF_INET == addr.ss_family)
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		addr4->sin_addr.s_addr = 0U;
		strcpy(straddr, "0.0.0.0");
	}
	else
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		memset(&(addr6->sin6_addr.s6_addr), 0, 16);
		strcpy(straddr, "::");
	}
}

const char *CIp::GetAddress() const
{
	if (straddr[0])
		return straddr;

	if (AF_INET == addr.ss_family)
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		inet_ntop(AF_INET, &(addr4->sin_addr), straddr, INET6_ADDRSTRLEN);
	}
	else if (AF_INET6 == addr.ss_family)
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		inet_ntop(AF_INET6, &(addr6->sin6_addr), straddr, INET6_ADDRSTRLEN);
	}
	else
	{
		std::cerr << "CIp::GetAddress: unknown socket family=" << addr.ss_family << std::endl;
	}
	return straddr;
}

std::ostream &operator<<(std::ostream &stream, const CIp &Ip)
{
	const char *sz = Ip;
	if (AF_INET6 == Ip.GetFamily())
		stream << "[" << sz << "]";
	else
		stream << sz;
	const uint16_t port = Ip.GetPort();
	if (port)
		stream << ":" << port;
	return stream;
}

uint32_t CIp::GetAddr() const
{
	if (AF_INET6 == addr.ss_family)
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		// hash the results
		auto *a = (const uint32_t *)&(addr6->sin6_addr.s6_addr);
		return a[0] ^ a[1] ^ a[2] ^ a[3];
	}
	else
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		return addr4->sin_addr.s_addr;
	}
}

int CIp::GetFamily() const
{
	return addr.ss_family;
}

uint16_t CIp::GetPort() const
{
	if (AF_INET == addr.ss_family)
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		return ntohs(addr4->sin_port);
	}
	else if (AF_INET6 == addr.ss_family)
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		return ntohs(addr6->sin6_port);
	}
	else
		return 0;
}

void CIp::SetPort(const uint16_t newport)
{
	if (AF_INET == addr.ss_family)
	{
		auto addr4 = (struct sockaddr_in *)&addr;
		addr4->sin_port = htons(newport);
	}
	else if (AF_INET6 == addr.ss_family)
	{
		auto addr6 = (struct sockaddr_in6 *)&addr;
		addr6->sin6_port = htons(newport);
	}
}

struct sockaddr *CIp::GetPointer()
{
	memset(straddr, 0, INET6_ADDRSTRLEN);	// things might change
	return (struct sockaddr *)&addr;
}

const struct sockaddr *CIp::GetCPointer() const
{
	return (const struct sockaddr *)&addr;
}

size_t CIp::GetSize() const
{
	if (AF_INET == addr.ss_family)
		return sizeof(struct sockaddr_in);
	else
		return sizeof(struct sockaddr_in6);
}

void CIp::Clear()
{
	memset(&addr, 0, sizeof(struct sockaddr_storage));
	memset(straddr, 0, INET6_ADDRSTRLEN);
	is_set = false;
}
