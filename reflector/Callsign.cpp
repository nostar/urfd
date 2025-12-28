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


#include <string.h>
#include <cctype>
#include "Global.h"
#include "Callsign.h"

// if a client is using special characters '.', '-' or '/', he's out of luck!
#define M17CHARACTERS " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/."

////////////////////////////////////////////////////////////////////////////////////////
// constructors

CCallsign::CCallsign()
{
	// blank all
	m_Callsign.l = 0x2020202020202020ul;
	m_Suffix.u = 0x20202020u;
	m_Module = ' ';
	m_uiDmrid = 0;
	m_coded = 0;
}

CCallsign::CCallsign(const std::string &cs, uint32_t dmrid, uint16_t nxdnid) : CCallsign()
{
	// and populate
	m_uiDmrid = dmrid;
	m_uiNXDNid = nxdnid;
	auto len = cs.size();
	if ( len > 0 )
	{
		// callsign valid
		memcpy(m_Callsign.c, cs.c_str(), MIN(len, CALLSIGN_LEN-1));
		if ( len >= CALLSIGN_LEN )
		{
			m_Module = cs.back();
		}

		auto key = GetKey();
		if (0 == m_uiDmrid)
		{
			g_LDid.Lock();
			m_uiDmrid = g_LDid.FindDmrid(key);
			g_LDid.Unlock();
		}

		if (0 == m_uiNXDNid)
		{
			g_LNid.Lock();
			m_uiNXDNid = g_LNid.FindNXDNid(key);
			g_LNid.Unlock();
		}
	}
	else if (dmrid)
	{
		g_LDid.Lock();
		auto pItem = g_LDid.FindCallsign(dmrid);
		if (pItem)
			m_Callsign = *pItem;
		g_LDid.Unlock();

		if (m_Callsign.l && 0 == nxdnid)
		{
			g_LNid.Lock();
			m_uiNXDNid = g_LNid.FindNXDNid(GetKey());
			g_LNid.Unlock();
		}
	}
	else if (nxdnid)
	{
		g_LNid.Lock();
		auto pItem = g_LNid.FindCallsign(nxdnid);
		if (pItem)
			m_Callsign = *pItem;
		g_LNid.Unlock();

		if (m_Callsign.l && 0 == dmrid)
		{
			g_LDid.Lock();
			m_uiDmrid = g_LDid.FindDmrid(GetKey());
			g_LDid.Unlock();
		}
	}
	if (m_Callsign.l)
		CSIn();
}

CCallsign::CCallsign(const CCallsign &cs)
{
	m_Callsign.l = cs.m_Callsign.l;
	m_Suffix.u = cs.m_Suffix.u;
	m_Module = cs.m_Module;
	m_uiDmrid = cs.m_uiDmrid;
	m_uiNXDNid = cs.m_uiNXDNid;
	m_coded = cs.m_coded;
}

CCallsign::CCallsign(const UCallsign &ucs) : CCallsign()
{
	m_Callsign.l = ucs.l;
}

CCallsign &CCallsign::operator = (const CCallsign &cs)
{
	if (this != &cs)
	{
		m_Callsign.l = cs.m_Callsign.l;
		m_Suffix.u = cs.m_Suffix.u;
		m_Module = cs.m_Module;
		m_uiDmrid = cs.m_uiDmrid;
		m_uiNXDNid = cs.m_uiNXDNid;
		m_coded = cs.m_coded;
	}
	return *this;
}

////////////////////////////////////////////////////////////////////////////////////////
// status

bool CCallsign::IsValid(void) const
{
	bool valid = true;
	int i;

	// callsign
	// first 3 chars are letter or number but cannot be all number
	int iNum = 0;
	for ( i = 0; i < 3; i++ )
	{
		valid = valid && (IsLetter(m_Callsign.c[i]) || IsNumber(m_Callsign.c[i]));
		if ( IsNumber(m_Callsign.c[i]) )
		{
			iNum++;
		}
	}
	// valid = valid && (iNum < 3); // Allow numeric callsigns (e.g. M17, DMR IDs)
	// all remaining char are letter, number or space
	for ( ; i < CALLSIGN_LEN; i++)
	{
		valid = valid && (IsLetter(m_Callsign.c[i]) || IsNumber(m_Callsign.c[i]) || IsSpace(m_Callsign.c[i]) || m_Callsign.c[i] == '-' || m_Callsign.c[i] == '.' || m_Callsign.c[i] == '/');
	}

	// prefix
	// all chars are number, letter, special char, or space
	for ( i = 0; i < CALLSUFFIX_LEN; i++ )
	{
		 valid = valid && (IsLetter(m_Suffix.c[i]) || IsNumber(m_Suffix.c[i]) || IsSpace(m_Suffix.c[i]) || IsLetterLC(m_Suffix.c[i]) || IsSpecialChar(m_Suffix.c[i]));
	}

	// module
	// is an letter or space
	valid = valid && (IsLetter(m_Module) || IsSpace(m_Module));

	// dmr and nxdn id is not tested, as it can be 0 if station is not registered

	// done
	return valid;
}

bool CCallsign::HasSuffix(void) const
{
	return 0x20202020u != m_Suffix.u;
}

////////////////////////////////////////////////////////////////////////////////////////
// set

void CCallsign::SetCallsign(const std::string &s, bool updateids)
{
	// set callsign
	memset(m_Callsign.c, ' ', CALLSIGN_LEN);
	m_Module = ' ';
	auto len = s.size();
	memcpy(m_Callsign.c, s.c_str(), MIN(len, CALLSIGN_LEN-1));
	if ( len >= CALLSIGN_LEN )
	{
		m_Module = s.back();
	}
	// update M17 coded callsign
	CSIn();
	// and update dmrid
	if (updateids)
	{
		auto key = GetKey();
		g_LDid.Lock();
		{
			m_uiDmrid = g_LDid.FindDmrid(key);
		}
		g_LDid.Unlock();
		g_LNid.Lock();
		{
			m_uiNXDNid = g_LNid.FindNXDNid(key);
		}
		g_LNid.Unlock();
	}
}

void CCallsign::SetCallsign(const uint8_t *buffer, int len, bool updateids)
{
	// set callsign
	memset(m_Callsign.c, ' ', CALLSIGN_LEN);
	m_Module = ' ';
	memcpy(m_Callsign.c, buffer, MIN(len, (int)CALLSIGN_LEN-1));
	for ( unsigned i = 0; i < CALLSIGN_LEN; i++ )
	{
		if ( m_Callsign.c[i] == 0 )
		{
			m_Callsign.c[i] = ' ';
		}
	}
	if ( (len >= (int)CALLSIGN_LEN) && ((char)buffer[CALLSIGN_LEN-1] != 0) )
	{
		m_Module = (char)buffer[CALLSIGN_LEN-1];
	}
	CSIn();
	if (updateids)
	{
		auto key = GetKey();
		g_LDid.Lock();
		{
			m_uiDmrid = g_LDid.FindDmrid(key);
		}
		g_LDid.Unlock();
		g_LNid.Lock();
		{
			m_uiNXDNid = g_LNid.FindNXDNid(key);
		}
		g_LNid.Unlock();
	}
}

void CCallsign::SetDmrid(uint32_t dmrid, bool UpdateCallsign)
{
	m_uiDmrid = dmrid;
	if ( UpdateCallsign )
	{
		g_LDid.Lock();
		{
			auto callsign = g_LDid.FindCallsign(dmrid);
			if ( callsign != nullptr )
			{
				m_Callsign.l = callsign->l;
			}
		}
		g_LDid.Unlock();
		CSIn();
	}
}

void CCallsign::SetDmrid(const uint8_t *buffer, bool UpdateCallsign)
{
	char sz[9];
	memcpy(sz, buffer, 8);
	sz[8] = 0;
	SetDmrid((uint32_t)::strtol(sz, nullptr, 16), UpdateCallsign);
}

void CCallsign::SetNXDNid(uint16_t nxdnid, bool UpdateCallsign)
{
	m_uiNXDNid = nxdnid;
	if ( UpdateCallsign )
	{
		g_LNid.Lock();
		{
			auto callsign = g_LNid.FindCallsign(nxdnid);
			if ( callsign != nullptr )
			{
				m_Callsign.l = callsign->l;
			}
		}
		g_LNid.Unlock();
		CSIn();
	}
}

void CCallsign::SetNXDNid(const uint8_t *buffer, bool UpdateCallsign)
{
	char sz[9];
	memcpy(sz, buffer, 8);
	sz[8] = 0;
	SetNXDNid((uint16_t)::strtol(sz, nullptr, 16), UpdateCallsign);
}

void CCallsign::SetCSModule(char c)
{
	m_Module = c;
	CSIn();
}


void CCallsign::SetSuffix(const std::string &s)
{
	memset(m_Suffix.c, ' ', CALLSUFFIX_LEN);
	memcpy(m_Suffix.c, s.c_str(), MIN(s.size(), CALLSUFFIX_LEN));
}

void CCallsign::SetSuffix(const uint8_t *buffer, int len)
{
	len = MIN(len, (int)CALLSUFFIX_LEN);
	memset(m_Suffix.c, ' ', CALLSUFFIX_LEN);
	memcpy(m_Suffix.c, buffer, len);
}

////////////////////////////////////////////////////////////////////////////////////////
// modify

void CCallsign::PatchCallsign(int off, const char *patch, int len)
{
	if ( off < CALLSIGN_LEN )
	{
		memcpy(m_Callsign.c, patch, MIN(len, (int)CALLSIGN_LEN - off));
	}
	CSIn();
}


////////////////////////////////////////////////////////////////////////////////////////
// get

UCallsign CCallsign::GetKey() const
{
	UCallsign rval;
	rval.l = 0x2020202020202020ul;
	for (unsigned i=0; i<CALLSIGN_LEN; i++)
	{
		auto c = m_Callsign.c[i];
		if (IsLetter(c) || IsNumber(c))
			rval.c[i] = c;
		else
			break;
	}
	return rval;
}

std::string CCallsign::GetBase() const
{
	auto u = GetKey();
	std::string rval(u.c, CALLSIGN_LEN);
	auto pos = rval.find(' ');
	if (std::string::npos != pos)
		rval.resize(pos);
	return rval;
}

void CCallsign::GetCallsign(uint8_t *buffer) const
{
	memcpy(buffer, m_Callsign.c, CALLSIGN_LEN);
	if ( HasModule() )
	{
		buffer[CALLSIGN_LEN-1] = m_Module;
	}
}

void CCallsign::GetCallsignString(char *sz) const
{
	unsigned i;
	for ( i = 0; (i < CALLSIGN_LEN) && (m_Callsign.c[i] != ' '); i++ )
	{
		sz[i] = m_Callsign.c[i];
	}
	sz[i] = 0;
}

const std::string CCallsign::GetCS() const
{
	std::string rval(m_Callsign.c, CALLSIGN_LEN);
	if (' ' != m_Module)
		rval.append(1, m_Module);
	return rval;
}

void CCallsign::GetSuffix(uint8_t *buffer) const
{
	memcpy(buffer, m_Suffix.c, CALLSUFFIX_LEN);
}

////////////////////////////////////////////////////////////////////////////////////////
// compare

bool CCallsign::HasSameCallsign(const CCallsign &cs) const
{
	return (memcmp(m_Callsign.c, cs.m_Callsign.c, CALLSIGN_LEN) == 0);
}

bool CCallsign::HasSameCallsignWithWildcard(const CCallsign &cs) const
{
	bool same = true;
	bool done = false;

	for ( unsigned i = 0; (i < CALLSIGN_LEN) && same && !done; i++ )
	{
		if ( !(done = ((m_Callsign.c[i] == '*') || (cs.m_Callsign.c[i] == '*'))) )
		{
			same = same && (m_Callsign.c[i] == cs.m_Callsign.c[i]);
		}
	}
	return same;
}


////////////////////////////////////////////////////////////////////////////////////////
// operators

bool CCallsign::operator ==(const CCallsign &cs) const
{
	return (cs.m_Callsign.l == m_Callsign.l) && (m_Module == cs.m_Module) && (cs.m_Suffix.u == m_Suffix.u) && (m_uiDmrid == cs.m_uiDmrid) && (m_uiNXDNid == cs.m_uiNXDNid);
}

CCallsign::operator const char *() const
{
	static char sz[CALLSIGN_LEN+CALLSUFFIX_LEN+5];

	// empty
	memset(sz, 0, sizeof(sz));
	// callsign
	memcpy(sz, m_Callsign.c, CALLSIGN_LEN);
	// module
	if ( HasModule() )
	{
		sz[CALLSIGN_LEN] = m_Module;
	}
	// suffix
	if ( HasSuffix() )
	{
		::strcat(sz, " / ");
		::strncat(sz, m_Suffix.c, CALLSUFFIX_LEN);
	}

	// done
	return sz;
}

////////////////////////////////////////////////////////////////////////////////////////
// helper

bool CCallsign::IsNumber(char c) const
{
	return ((c >= '0') && (c <= '9'));
}

bool CCallsign::IsLetter(char c) const
{
	return ((c >= 'A') && (c <= 'Z'));
}

bool CCallsign::IsSpace(char c) const
{
	return (c == ' ');
}

bool CCallsign::IsLetterLC(char c) const
{
	return ((c >= 'a') && (c <= 'z'));
}

bool CCallsign::IsSpecialChar(char c) const
{
    return ((c >= '!') && (c <= '/'));
}

void CCallsign::CodeIn(const uint8_t *in)
{
	char cs[10];
	const std::string m17_alphabet(M17CHARACTERS);
	memset(cs, 0, 10);
	m_coded = in[0];
	for (int i=1; i<6; i++)
		m_coded = (m_coded << 8) | in[i];
	if (m_coded > 0xee6b27ffffffu) {
		std::cerr << "Callsign code is too large, 0x" << std::hex << m_coded << std::dec << std::endl;
		return;
	}
	auto c = m_coded;
	int i = 0;
	while (c) {
		cs[i++] = m17_alphabet[c % 40];
		c /= 40;
	}
	SetCallsign(cs);
}

void CCallsign::CodeOut(uint8_t *out) const
{
	memset(out, 0, 6);
	auto c = m_coded;
	auto pout = out+5;
	while (c)
	{
		*pout-- = c % 0x100u;
		c /= 0x100u;
	}
}

// called to calculate the m17 encoded cs
void CCallsign::CSIn()
{
	const std::string m17_alphabet(M17CHARACTERS);
	auto pos = m17_alphabet.find(m_Module);
	m_coded = pos;
	m_coded *= 40;
	for( int i=CALLSIGN_LEN-2; i>=0; i-- ) {
		pos = m17_alphabet.find(m_Callsign.c[i]);
		if (pos == std::string::npos) {
			pos = 0;
		}
		m_coded *= 40;
		m_coded += pos;
	}
}
