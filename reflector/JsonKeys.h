/*
 *   Copyright (c) 2023 by Thomas A. Early N7TAE
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string>

#pragma once

// configuration key names
struct SJsonKeys {
	struct PORTONLY { const std::string port; }
	dcs { "DCSPort" },
	dextra { "DExtraPort" },
	dmrplus { "DMRPlusPort" },
	dplus { "DPlusPort" },
	m17 { "M17Port" },
	urf { "URFPort" };

	struct G3 { const std::string enable; }
	g3 { "G3Enable" };

	struct BM { const std::string enable, port; }
	bm { "bmEnable", "bmPort" };

	struct IMRS { const std::string enable, port; }
	imrs { "IMRSEnable", "IMRSPort" };

	struct MMDVM { const std::string port, defaultid; }
	mmdvm { "MMDVMPort", "mmdvmdefaultid" };

	struct NAMES { const std::string callsign, bootstrap, url, email, country, sponsor; }
	names { "Callsign", "bootstrap", "DashboardUrl", "SysopEmail", "Country", "Sponsor" };

	struct IP { const std::string ipv4bind, ipv4address, ipv6bind, ipv6address; }
	ip { "ipv4bind", "IPv4Address", "ipv6bind", "IPv6Address" };

	struct TC { const std::string port, bind, modules; }
	tc { "tcport", "tcbind", "TranscodedModules" };

	struct MODULES { const std::string modules, descriptor[26]; }
	modules { "Modules",
		"DescriptionA", "DescriptionB", "DescriptionC", "DescriptionD", "DescriptionE", "DescriptionF", "DescriptionG", "DescriptionH", "DescriptionI", "DescriptionJ", "DescriptionK", "DescriptionL", "DescriptionM", "DescriptionN", "DescriptionO", "DescriptionP", "DescriptionQ", "DescriptionR", "DescriptionS", "DescriptionT", "DescriptionU", "DescriptionV", "DescriptionW", "DescriptionX", "DescriptionY", "DescriptionZ" };

	struct USRP { const std::string enable, ip, txport, rxport, module, callsign, filepath; }
	usrp { "usrpEnable", "usrpIpAddress", "urspTxPort", "usrpRxPort", "usrpModule", "usrpCallsign", "usrpFilePath" };

	struct P25NXDN { const std::string port, autolinkmod, reflectorid; }
	p25 { "P25Port",  "P25AutolinkMod",   "P25ReflectorID" },
	nxdn { "NXDNPort", "NXDNAutolinkMod", "NXDNReflectorID" };

	struct YSF { const std::string port, autolinkmod, enabledgid, defaulttxfreq, defaultrxfreq;
		struct YSLREG { const std::string id, name, description; } ysfreflectordb; }
	ysf { "YSFPort", "YSFAutoLinkMod", "YSFEnableDGID", "YSFDefaultTxFreq", "YSFDefaultRxFreq",
		{ "ysfrefdbid", "ysfrefdbname", "ysfrefdbdesc" } };

	struct DB { const std::string url, mode, refreshmin, filepath; }
	dmriddb   {  "dmrIdDbUrl",  "dmrIdDbMode",  "dmrIdDbRefresh",  "dmrIdDbFilePath" },
	nxdniddb  { "nxdnIdDbUrl", "nxdnIdDbMode", "nxdnIdDbRefresh", "nxdnIdDbFilePath" },
	ysftxrxdb {  "ysfIdDbUrl",  "ysfIdDbMode",  "ysfIdDbRefresh",  "ysfIdDbFilePath" };

	struct FILES { const std::string pid, xml, json, white, black, interlink, terminal; }
	files { "pidFilePath", "xmlFilePath", "jsonFilePath", "whitelistFilePath", "blacklistFilePath", "interlinkFilePath", "g3TerminalFilePath" };

	struct DASHBOARD { const std::string enable, nngaddr, interval; }
	dashboard { "DashboardEnable", "DashboardNNGAddr", "DashboardInterval" };
};
