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

#pragma once

#include <vector>
#include <fstream>
#include <cstdint>

////////////////////////////////////////////////////////////////////////////////////////

class CBuffer
{
public:
	CBuffer() {}
	CBuffer(uint8_t *, int);

	// destructor
	virtual ~CBuffer() {};

	// set
	void Set(uint8_t *, int);
	void Set(const char *);
	void Append(const uint8_t *, int);
	void Append(uint8_t, int);
	void Append(uint8_t);
	void Append(uint16_t);
	void Append(uint32_t);
	void Append(const char *);
	void ReplaceAt(int, uint8_t);
	void ReplaceAt(int, uint16_t);
	void ReplaceAt(int, uint32_t);
	void ReplaceAt(int, const uint8_t *, int);

	// operation
	int Compare(const uint8_t *, int) const;
	int Compare(const uint8_t *, int, int) const;

	// operator
	bool operator ==(const CBuffer &) const;
	bool operator ==(const char *) const;
	operator const char *() const;

	// debug
	void DebugDump(std::ofstream &) const;
	void DebugDumpAscii(std::ofstream &) const;
	void Dump(const std::string &title);

	// pass through
	void clear() { m_data.clear(); }
	void reserve(unsigned int size) { m_data.reserve(size); }
	std::vector<uint8_t>::size_type size() const { return m_data.size(); }
	uint8_t *data() { return m_data.data(); }
	const uint8_t *data() const { return m_data.data(); }
	void resize(std::vector<uint8_t>::size_type len, uint8_t val = 0) { m_data.resize(len, val); }
	uint8_t at(std::vector<uint8_t>::size_type i) const { return m_data.at(i); }

protected:
	std::vector<uint8_t> m_data;
};
