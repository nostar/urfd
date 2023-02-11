//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.

// urfd -- The universal reflector
// Copyright © 2023 Thomas A. Early N7TAE
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
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

#include "Reflector.h"
#include "LookupDmr.h"

extern CReflector g_ref;
extern CConfigure g_cfg;

void CLookupDmr::ClearContents()
{
	m_CallsignMap.clear();
	m_DmridMap.clear();
}

void CLookupDmr::LoadParameters()
{
	g_cfg.GetRefreshType(g_cfg.j.dmriddb.mode, m_Type);
	g_cfg.GetUnsigned(g_cfg.j.dmriddb.refreshmin, m_Refresh);
	g_cfg.GetString(g_cfg.j.dmriddb.filepath, m_Path);
	g_cfg.GetString(g_cfg.j.dmriddb.hostname, m_Host);
	g_cfg.GetString(g_cfg.j.dmriddb.suffix, m_Suffix);
}

uint32_t CLookupDmr::FindDmrid(const CCallsign &callsign)
{

	auto found = m_DmridMap.find(callsign);
	if ( found != m_DmridMap.end() )
	{
		return (found->second);
	}
	return 0;
}

const CCallsign *CLookupDmr::FindCallsign(uint32_t dmrid)
{
	auto found = m_CallsignMap.find(dmrid);
	if ( found != m_CallsignMap.end() )
	{
		return &(found->second);
	}
	return nullptr;
}

bool CLookupDmr::LoadContentFile(CBuffer &buffer)
{
	buffer.clear();
	std::ifstream file;
	std::streampos size;

	// open file
	file.open(m_Path, std::ios::in | std::ios::binary | std::ios::ate);
	if ( file.is_open() )
	{
		// read file
		size = file.tellg();
		if ( size > 0 )
		{
			// read file into buffer
			buffer.resize((int)size+1);
			file.seekg(0, std::ios::beg);
			file.read((char *)buffer.data(), (int)size);

			// close file
			file.close();
		}
	}

	// done
	return buffer.size() > 0;
}

bool CLookupDmr::LoadContentHttp(CBuffer &buf)
{
	// get file from xlxapi server
	return HttpGet(m_Host.c_str(), m_Suffix.c_str(), 80, buf);
}

void CLookupDmr::RefreshContentFile(const CBuffer &buffer)
{
	// crack it
	char *ptr1 = (char *)buffer.data();
	char *ptr2;

	// get next line
	while ( (ptr2 = strchr(ptr1, '\n')) != nullptr )
	{
		*ptr2 = 0;
		// get items
		char *dmrid;
		char *callsign;
		if ( ((dmrid = strtok(ptr1, ";")) != nullptr) && IsValidDmrId(dmrid) )
		{
			if ( ((callsign = ::strtok(nullptr, ";")) != nullptr) )
			{
				// new entry
				uint32_t ui = atoi(dmrid);
				CCallsign cs(callsign, ui);
				if ( cs.IsValid() )
				{
					m_CallsignMap.insert(std::pair<uint32_t,CCallsign>(ui, cs));
					m_DmridMap.insert(std::pair<CCallsign,uint32_t>(cs,ui));
				}
			}
		}
		// next line
		ptr1 = ptr2+1;
	}

	std::cout << "Read " << m_DmridMap.size() << " DMR ids from file " << m_Refresh << std::endl;
}

void CLookupDmr::RefreshContentHttp(const CBuffer &buffer)
{
	char *ptr1 = (char *)buffer.data();
	char *ptr2;
	// get next line
	while ( (ptr2 = strchr(ptr1, '\n')) != nullptr )
	{
		*ptr2 = 0;
		// get items
		char *dmrid;
		char *callsign;
		if ( ((dmrid = strtok(ptr1, ";")) != nullptr) && IsValidDmrId(dmrid) )
		{
			if ( ((callsign = strtok(nullptr, ";")) != nullptr) )
			{
				// new entry
				uint32_t ui = atoi(dmrid);
				CCallsign cs(callsign, ui);
				if ( cs.IsValid() )
				{
					m_CallsignMap.insert(std::pair<uint32_t, CCallsign>(ui, cs));
					m_DmridMap.insert(std::pair<CCallsign, uint32_t>(cs,ui));
				}
			}
		}
		// next line
		ptr1 = ptr2+1;
	}

	std::cout << "Read " << m_DmridMap.size() << " DMR ids from " << m_Host << " database " << std::endl;
}

bool CLookupDmr::IsValidDmrId(const char *sz)
{
	bool ok = false;
	size_t n = strlen(sz);
	if ( (n > 0) && (n <= 8) )
	{
		ok = true;
		for ( size_t i = 0; (i < n) && ok; i++ )
		{
			ok = ok && isdigit(sz[i]);
		}
	}
	return ok;
}

#define DMRID_HTTPGET_SIZEMAX       (256)

bool CLookupDmr::HttpGet(const char *hostname, const char *filename, int port, CBuffer &buffer)
{
	buffer.clear();
	int sock_id;

	// open socket
	if ( (sock_id = socket(AF_INET, SOCK_STREAM, 0)) >= 0 )
	{
		// get hostname address
		struct sockaddr_in servaddr;
		struct hostent *hp;
		memset(&servaddr, 0, sizeof(servaddr));
		if( (hp = gethostbyname(hostname)) != nullptr)
		{
			// dns resolved
			memcpy((char *)&servaddr.sin_addr.s_addr, (char *)hp->h_addr, hp->h_length);
			servaddr.sin_port = htons(port);
			servaddr.sin_family = AF_INET;

			// connect
			if (connect(sock_id, (struct sockaddr *)&servaddr, sizeof(servaddr)) == 0)
			{
				// send the GET request
				char request[DMRID_HTTPGET_SIZEMAX];
				::sprintf(request, "GET /%s HTTP/1.0\r\nFrom: %s\r\nUser-Agent: urfd\r\n\r\n", filename, g_ref.GetCallsign().GetCS().c_str());
				::write(sock_id, request, strlen(request));

				// config receive timeouts
				fd_set read_set;
				struct timeval timeout;
				timeout.tv_sec = 5;
				timeout.tv_usec = 0;
				FD_ZERO(&read_set);
				FD_SET(sock_id, &read_set);

				// get the reply back
				bool done = false;
				do
				{
					char buf[1440];
					ssize_t len = 0;
					select(sock_id+1, &read_set, nullptr, nullptr, &timeout);
					//if ( (ret > 0) || ((ret < 0) && (errno == EINPROGRESS)) )
					//if ( ret >= 0 )
					//{
					usleep(5000);
					len = read(sock_id, buf, 1440);
					if ( len > 0 )
					{
						buffer.Append((uint8_t *)buf, (int)len);
					}
					//}
					done = (len <= 0);

				}
				while (!done);
				buffer.Append((uint8_t)0);

				// and disconnect
				close(sock_id);
			}
			else
			{
				std::cout << "Cannot establish connection with host " << hostname << std::endl;
			}
		}
		else
		{
			std::cout << "Host " << hostname << " not found" << std::endl;
		}

	}
	else
	{
		std::cout << "Failed to open wget socket" << std::endl;
	}

	// done
	return buffer.size() > 1;
}