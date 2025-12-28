//
//  Copyright © 2020 Thomas A. Early, N7TAE
//
// ----------------------------------------------------------------------------
//
//    m17ref is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    m17ref is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    with this software.  If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------

#include <arpa/inet.h>

#include "M17Packet.h"

CM17Packet::CM17Packet(const uint8_t *buf, bool isStandard)
    : m_isStandard(isStandard)
{
    if (m_isStandard)
    {
        memcpy(m_frame.buffer, buf, sizeof(SM17FrameStandard));
        destination.CodeIn(m_frame.standard.lich.addr_dst);
        source.CodeIn(m_frame.standard.lich.addr_src);
    }
    else
    {
        memcpy(m_frame.buffer, buf, sizeof(SM17FrameLegacy));
        destination.CodeIn(m_frame.legacy.lich.addr_dst);
        source.CodeIn(m_frame.legacy.lich.addr_src);
    }
}

const CCallsign &CM17Packet::GetDestCallsign() const
{
	return destination;
}

const CCallsign &CM17Packet::GetSourceCallsign() const
{
	return source;
}

char CM17Packet::GetDestModule() const
{
	return destination.GetCSModule();
}

uint16_t CM17Packet::GetFrameNumber() const
{
    if (m_isStandard)
        return ntohs(m_frame.standard.framenumber);
    else
        return ntohs(m_frame.legacy.framenumber);
}

uint16_t CM17Packet::GetFrameType() const
{
    if (m_isStandard)
        return ntohs(m_frame.standard.lich.frametype);
    else
        return ntohs(m_frame.legacy.lich.frametype);
}

const uint8_t *CM17Packet::GetPayload() const
{
    if (m_isStandard)
        return m_frame.standard.payload;
    else
        return m_frame.legacy.payload;
}

const uint8_t *CM17Packet::GetNonce() const
{
    if (m_isStandard)
        return m_frame.standard.lich.nonce;
    else
        return m_frame.legacy.lich.nonce;
}

void CM17Packet::SetPayload(const uint8_t *newpayload)
{
    if (m_isStandard)
        memcpy(m_frame.standard.payload, newpayload, 16);
    else
        memcpy(m_frame.legacy.payload, newpayload, 16);
}

uint16_t CM17Packet::GetStreamId() const
{
    if (m_isStandard)
        return ntohs(m_frame.standard.streamid);
    else
        return ntohs(m_frame.legacy.streamid);
}

uint16_t CM17Packet::GetCRC() const
{
    if (m_isStandard)
        return ntohs(m_frame.standard.crc);
    else
        return ntohs(m_frame.legacy.crc);
}

void CM17Packet::SetCRC(uint16_t crc)
{
    if (m_isStandard)
        m_frame.standard.crc = htons(crc);
    else
        m_frame.legacy.crc = htons(crc);
}

void CM17Packet::SetDestCallsign(const CCallsign &cs)
{
    destination = cs;
    if (m_isStandard)
        destination.CodeOut(m_frame.standard.lich.addr_dst);
    else
        destination.CodeOut(m_frame.legacy.lich.addr_dst);
}

void CM17Packet::SetSourceCallsign(const CCallsign &cs)
{
    source = cs;
    if (m_isStandard)
        source.CodeOut(m_frame.standard.lich.addr_src);
    else
        source.CodeOut(m_frame.legacy.lich.addr_src);
}

void CM17Packet::SetStreamId(uint16_t id)
{
    if (m_isStandard)
        m_frame.standard.streamid = htons(id);
    else
        m_frame.legacy.streamid = htons(id);
}

void CM17Packet::SetFrameNumber(uint16_t fn)
{
    if (m_isStandard)
        m_frame.standard.framenumber = htons(fn);
    else
        m_frame.legacy.framenumber = htons(fn);
}

void CM17Packet::SetFrameType(uint16_t ft)
{
    if (m_isStandard)
        m_frame.standard.lich.frametype = htons(ft);
    else
        m_frame.legacy.lich.frametype = htons(ft);
}

void CM17Packet::SetMagic()
{
    if (m_isStandard)
        memcpy(m_frame.standard.magic, "M17 ", 4);
    else
        memcpy(m_frame.legacy.magic, "M17 ", 4);
}

void CM17Packet::SetNonce(const uint8_t *nonce)
{
    if (m_isStandard)
        memcpy(m_frame.standard.lich.nonce, nonce, 14);
    else
        memcpy(m_frame.legacy.lich.nonce, nonce, 14);
}

bool CM17Packet::IsLastPacket() const
{
    if (m_isStandard)
        return ((0x8000u & ntohs(m_frame.standard.framenumber)) == 0x8000u);
    else
        return ((0x8000u & ntohs(m_frame.legacy.framenumber)) == 0x8000u);
}
