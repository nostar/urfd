#pragma once


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
#include <cstring>
#include <chrono>
#include <thread>

#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

class CIp
{
public:
	// constructors
	CIp();
	CIp(const char *address, int family = AF_UNSPEC, int type = SOCK_DGRAM, uint16_t port = 0U);
	CIp(const int family, const uint16_t port = 0U, const char *address = nullptr);

	// initializer for empty constructor
	void Initialize(const int family, const uint16_t port = 0U, const char *address = nullptr);

	// comparison operators
	bool operator==(const CIp &rhs) const;
	// comparison operators
	bool operator!=(const CIp &rhs) const;
    bool operator<(const CIp &rhs) const;


	// state methods
	bool IsSet() const { 	return is_set;
}

	bool AddressIsZero() const;
	void ClearAddress();
	const char *GetAddress() const;
	operator const char *() const { return GetAddress(); }
	friend std::ostream &operator<<(std::ostream &stream, const CIp &Ip);
	int GetFamily() const;
	uint16_t GetPort() const;
	size_t GetSize() const;
	uint32_t GetAddr() const;

	// modifiers
	void SetPort(const uint16_t newport);

	// for i/o
	struct sockaddr *GetPointer();
	const struct sockaddr *GetCPointer() const;

	void Clear();

private:
	struct sockaddr_storage addr;
	mutable char straddr[INET6_ADDRSTRLEN];
	bool is_set;
};

std::ostream &operator<<(std::ostream &stream, const CIp &Ip);
