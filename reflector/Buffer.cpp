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
#include <string.h>
#include "Buffer.h"

////////////////////////////////////////////////////////////////////////////////////////
// constructor

CBuffer::CBuffer(uint8_t *buffer, int len)
{
	m_data.resize(len);
	memcpy(m_data.data(), buffer, len);
}

////////////////////////////////////////////////////////////////////////////////////////
// set

void CBuffer::Set(uint8_t *buffer, int len)
{
	m_data.resize(len);
	memcpy(m_data.data(), buffer, len);
}

void CBuffer::Set(const char *sz)
{
	m_data.resize(::strlen(sz)+1);
	::strcpy((char *)m_data.data(), sz);
}

void CBuffer::Append(const uint8_t *buffer, int len)
{
	int n = (int)m_data.size();
	m_data.resize(n+len);
	memcpy(&(m_data.data()[n]), buffer, len);
}

void CBuffer::Append(uint8_t ui, int len)
{
	int n = (int)m_data.size();
	m_data.resize(n+len);
	memset(&(m_data.data()[n]), ui, len);
}

void CBuffer::Append(uint8_t ui)
{
	int n = (int)m_data.size();
	m_data.resize(n+sizeof(uint8_t));
	memcpy(&(m_data.data()[n]), &ui, sizeof(uint8_t));
}

void CBuffer::Append(uint16_t ui)
{
	int n = (int)m_data.size();
	m_data.resize(n+sizeof(uint16_t));
	memcpy(&(m_data.data()[n]), &ui, sizeof(uint16_t));
}

void CBuffer::Append(uint32_t ui)
{
	int n = (int)m_data.size();
	m_data.resize(n+sizeof(uint32_t));
	memcpy(&(m_data.data()[n]), &ui, sizeof(uint32_t));
}

void CBuffer::Append(const char *sz)
{
	Append((uint8_t *)sz, (int)strlen(sz));
	Append((uint8_t)0x00);
}

void CBuffer::ReplaceAt(int i, uint8_t ui)
{
	if ( m_data.size() < (i+sizeof(uint8_t)) )
	{
		m_data.resize(i+sizeof(uint8_t));
	}
	*(uint8_t *)(&(m_data.data()[i])) = ui;
}

void CBuffer::ReplaceAt(int i, uint16_t ui)
{
	if ( m_data.size() < (i+sizeof(uint16_t)) )
	{
		m_data.resize(i+sizeof(uint16_t));
	}
	*(uint16_t *)(&(m_data.data()[i])) = ui;
}

void CBuffer::ReplaceAt(int i, uint32_t ui)
{
	if ( m_data.size() < (i+sizeof(uint32_t)) )
	{
		m_data.resize(i+sizeof(uint32_t));
	}
	*(uint32_t *)(&(m_data.data()[i])) = ui;
}

void CBuffer::ReplaceAt(int i, const uint8_t *ptr, int len)
{
	if ( m_data.size() < unsigned(i+len) )
	{
		m_data.resize(i+len);
	}
	memcpy(&(m_data.data()[i]), ptr, len);
}

////////////////////////////////////////////////////////////////////////////////////////
// operation

int CBuffer::Compare(const uint8_t *buffer, int len) const
{
	int result = -1;
	if ( m_data.size() >= unsigned(len) )
	{
		result = memcmp(m_data.data(), buffer, len);
	}
	return result;
}

int CBuffer::Compare(const uint8_t *buffer, int off, int len) const
{
	int result = -1;
	if ( m_data.size() >= unsigned(off+len) )
	{
		result = memcmp(&(m_data.data()[off]), buffer, len);
	}
	return result;
}


////////////////////////////////////////////////////////////////////////////////////////
// operator

bool CBuffer::operator ==(const CBuffer &Buffer) const
{
	if ( m_data.size() == Buffer.m_data.size() )
	{
		return (memcmp((const char *)m_data.data(), (const char *)Buffer.m_data.data(), m_data.size()) == 0);
	}
	return false;
}

bool CBuffer::operator ==(const char *sz) const
{
	if ( m_data.size() == ::strlen(sz) )
	{
		return (memcmp((const char *)m_data.data(), sz, m_data.size()) == 0);
	}
	return false;
}

CBuffer::operator const char *() const
{
	return (const char *)m_data.data();
}

////////////////////////////////////////////////////////////////////////////////////////
// debug

void CBuffer::DebugDump(std::ofstream &debugout) const
{
	// dump a hex line
	for ( unsigned int i = 0; i < m_data.size(); i++ )
	{
		char sz[16];
		//sprintf(sz, "%02X", m_data.data()[i]);
		sprintf(sz, "0x%02X", m_data.data()[i]);
		debugout << sz;
		if ( i == m_data.size()-1 )
		{
			debugout << std::endl;
		}
		else
		{
			debugout << ',';
		}
	}
}

void CBuffer::DebugDumpAscii(std::ofstream &debugout) const
{
	// dump an ascii line
	for ( unsigned int i = 0; i < m_data.size(); i++ )
	{
		char c = m_data.data()[i];
		if ( isascii(c) )
		{
			debugout << c;
		}
		else
		{
			debugout << '.';
		}
		if ( i == m_data.size()-1 )
		{
			debugout << std::endl;
		}
	}
}

void CBuffer::Dump(const std::string &title)
{
	std::cout << title << ":" << std::endl;

	unsigned int offset = 0U;
	unsigned int length = m_data.size();

	while (length > 0U) {
		std::string output;

		unsigned int bytes = (length > 16U) ? 16U : length;

		char temp[10U];
		for (unsigned i = 0U; i < bytes; i++) {
			::sprintf(temp, "%02X ", m_data[offset + i]);
			output += temp;
		}

		for (unsigned int i = bytes; i < 16U; i++)
			output += "   ";

		output += "   *";

		for (unsigned i = 0U; i < bytes; i++) {
			unsigned char c = m_data[offset + i];

			if (::isprint(c))
				output += c;
			else
				output += '.';
		}

		output += '*';

		::sprintf(temp, "%04X:  ", offset);
		std::cout << temp << output << std::endl;

		offset += 16U;

		if (length >= 16U)
			length -= 16U;
		else
			length = 0U;
	}
}
