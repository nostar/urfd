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

#include "Global.h"

CReflector::CReflector() {}

CReflector::~CReflector()
{
	keep_running = false;
	if ( m_MaintenanceFuture.valid() )
	{
		m_MaintenanceFuture.get();
	}

	for (auto it=m_Modules.cbegin(); it!=m_Modules.cend(); it++)
	{
		if (m_RouterFuture[*it].valid())
			m_RouterFuture[*it].get();
	}
	m_RouterFuture.clear();
	m_Stream.clear();
}


////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CReflector::Start(void)
{
	// get config stuff
	const auto cs(g_Configure.GetString(g_Keys.names.callsign));
	m_Callsign.SetCallsign(cs, false);
	m_Modules.assign(g_Configure.GetString(g_Keys.modules.modules));
	const auto tcmods(g_Configure.GetString(g_Keys.tc.modules));
	const auto port = g_Configure.GetUnsigned(g_Keys.tc.port);

#ifndef NO_DHT
	// start the dht instance
	refhash = dht::InfoHash::get(cs);
	node.run(17171, dht::crypto::generateIdentity(cs), true, 59973);
	node.bootstrap(g_Configure.GetString(g_Keys.names.bootstrap), "17171");
#endif

	// let's go!
	keep_running = true;

	// init transcoder comms
	if (port)
	{
		if (g_TCServer.Open(g_Configure.GetString(g_Keys.tc.bind), tcmods, port))
			return true;
	}

	// init gate keeper. It can only return true!
	g_GateKeeper.Init();

	// init dmrid directory. No need to check the return value.
	g_LDid.LookupInit();

	// init dmrid directory. No need to check the return value.
	g_LNid.LookupInit();

	// init wiresx node directory. Likewise with the return vale.
	g_LYtr.LookupInit();

	// create protocols
	if (! m_Protocols.Init())
	{
		m_Protocols.Close();
		return true;
	}

	// start one thread per reflector module
	for (auto c : m_Modules)
	{
		auto stream = std::make_shared<CPacketStream>(c);
		if (stream)
		{
			// if it's a transcoded module, then we need to initialize the codec stream
			if (port)
			{
				if (std::string::npos != tcmods.find(c))
				{
					if (stream->InitCodecStream())
						return true;
				}
			}
			m_Stream[c] = stream;
		}
		else
		{
			std::cerr << "Could not make a CPacketStream for module '" << c << "'" << std::endl;
			return true;
		}
		try
		{
			m_RouterFuture[c] = std::async(std::launch::async, &CReflector::RouterThread, this, c);
		}
		catch(const std::exception& e)
		{
			std::cerr << "Cannot start module '" << c << "' thread: " << e.what() << '\n';
			keep_running = false;
			return true;
		}
	}

	// start the reporting thread
	try
	{
		m_MaintenanceFuture = std::async(std::launch::async, &CReflector::MaintenanceThread, this);
	}
	catch(const std::exception& e)
	{
		std::cerr << "Cannot start the dashboard data report thread: " << e.what() << '\n';
	}

#ifndef NO_DHT
	PutDHTConfig();
#endif

	return false;
}

void CReflector::Stop(void)
{
	// stop & delete all threads
	keep_running = false;

	// stop transcoder comms
	// if it was never opened, then there is nothing to close;
	g_TCServer.Close();

	// stop & delete report threads
	if ( m_MaintenanceFuture.valid() )
	{
		m_MaintenanceFuture.get();
	}

	// stop & delete all router thread
	for (auto c : m_Modules)
	{
		if (m_RouterFuture[c].valid())
			m_RouterFuture[c].get();
	}

	// close protocols
	m_Protocols.Close();

	// close gatekeeper
	g_GateKeeper.Close();

	// close databases
	g_LDid.LookupClose();
	g_LNid.LookupClose();
	g_LYtr.LookupClose();

#ifndef NO_DHT
	// kill the DHT
	node.cancelPut(refhash, toUType(EUrfdValueID::Config));
	node.cancelPut(refhash, toUType(EUrfdValueID::Peers));
	node.cancelPut(refhash, toUType(EUrfdValueID::Clients));
	node.cancelPut(refhash, toUType(EUrfdValueID::Users));
	node.shutdown({}, true);
	node.join();
#endif
}

////////////////////////////////////////////////////////////////////////////////////////
// stream opening & closing

bool CReflector::IsStreaming(char module)
{
	return false;
}

// clients MUST have bee locked by the caller so we can freely access it within the function
std::shared_ptr<CPacketStream> CReflector::OpenStream(std::unique_ptr<CDvHeaderPacket> &DvHeader, std::shared_ptr<CClient>client)
{
	// check sid is not zero
	if ( 0U == DvHeader->GetStreamId() )
	{
		std::cerr << "StreamId for client " << client->GetCallsign() << " is zero!" << std::endl;
		return nullptr;
	}

	// check if client is valid candidate
	if ( ! m_Clients.IsClient(client) || client->IsAMaster() )
	{
		return nullptr;
	}

	// check if no stream with same streamid already open
	// to prevent loops
	if ( IsStreamOpen(DvHeader) )
	{
		std::cerr << "Detected stream loop on module " << DvHeader->GetRpt2Module() << " for client " << client->GetCallsign() << " with sid " << DvHeader->GetStreamId() << std::endl;
		return nullptr;
	}

	// set the packet module
	DvHeader->SetPacketModule(client->GetReflectorModule());
	// get the module's queue
	char module = DvHeader->GetRpt2Module();
	auto stream = GetStream(module);
	if ( stream == nullptr )
	{
		std::cerr << "Can't find module '" << module << "' for Client " << client->GetCallsign() << std::endl;
		return nullptr;
	}

	// is it available ?
	if ( stream->OpenPacketStream(*DvHeader, client) )
	{
		// stream open, mark client as master
		// so that it can't be deleted
		client->SetMasterOfModule(module);

		// update last heard time
		client->Heard();

		// report
		std::cout << std::showbase << std::hex;
		std::cout << "Opening stream on module " << module << " for client " << client->GetCallsign() << " with sid " << ntohs(DvHeader->GetStreamId()) << " by user " << DvHeader->GetMyCallsign() << std::endl;
		std::cout << std::noshowbase << std::dec;

		// and push header packet
		stream->Push(std::move(DvHeader));

		// notify
		//OnStreamOpen(stream->GetUserCallsign());

	}
	return stream;
}

void CReflector::CloseStream(std::shared_ptr<CPacketStream> stream)
{
	if ( stream != nullptr )
	{
		// wait queue is empty. this waits forever
		bool bEmpty = stream->IsEmpty();
		while (! bEmpty)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			bEmpty = stream->IsEmpty();
		}

		GetClients();	// lock clients

		// get and check the master
		std::shared_ptr<CClient>client = stream->GetOwnerClient();
		if ( client != nullptr )
		{
			// client no longer a master
			client->NotAMaster();

			// notify
			//OnStreamClose(stream->GetUserCallsign());

			std::cout << "Closing stream of module " << GetStreamModule(stream) << std::endl;
		}

		// release clients
		ReleaseClients();

		// and stop the queue
		stream->ClosePacketStream();
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// router threads

void CReflector::RouterThread(const char ThisModule)
{
	auto pitem = m_Stream.find(ThisModule);
	if (m_Stream.end() == pitem)
	{
		std::cerr << "Module '" << ThisModule << " CPacketStream doesn't exist! aborting RouterThread()" << std::endl;
		return;
	}
	const auto streamIn = pitem->second;
	while (keep_running)
	{
		// wait until something shows up
		auto packet = streamIn->PopWait();

		packet->SetPacketModule(ThisModule);

		// iterate on all protocols
		m_Protocols.Lock();
		for ( auto it=m_Protocols.begin(); it!=m_Protocols.end(); it++ )
		{
			auto copy = packet->Copy();

			// if packet is header, update RPT2 according to protocol
			if ( copy->IsDvHeader() )
			{
				// make the protocol-patched reflector callsign
				CCallsign csRPT = (*it)->GetReflectorCallsign();
				csRPT.SetCSModule(ThisModule);
				// and put it in the copy
				(dynamic_cast<CDvHeaderPacket *>(copy.get()))->SetRpt2Callsign(csRPT);
			}

			(*it)->Push(std::move(copy));
		}
		m_Protocols.Unlock();
	}
}

// Maintenance thread hands xml and/or json update,
// and also keeps the transcoder TCP port(s) connected
#define XML_UPDATE_PERIOD 10

void CReflector::MaintenanceThread()
{
	std::string xmlpath, jsonpath;
	if (g_Configure.Contains(g_Keys.files.xml))
		xmlpath.assign(g_Configure.GetString(g_Keys.files.xml));
	if (g_Configure.Contains(g_Keys.files.json))
		jsonpath.assign(g_Configure.GetString(g_Keys.files.json));
	auto tcport = g_Configure.GetUnsigned(g_Keys.tc.port);

	if (xmlpath.empty() && jsonpath.empty())
		return;	// nothing to do

	while (keep_running)
	{
		// report to xml file
		if (! xmlpath.empty())
		{
			std::ofstream xmlFile;
			xmlFile.open(xmlpath, std::ios::out | std::ios::trunc);
			if ( xmlFile.is_open() )
			{
				// write xml file
				WriteXmlFile(xmlFile);

				// and close file
				xmlFile.close();
			}
			else
			{
				std::cout << "Failed to open " << xmlpath  << std::endl;
			}
		}

		// json report
		if (!  jsonpath.empty())
		{
			nlohmann::json jreport;
			JsonReport(jreport);
			std::ofstream jsonFile;
			jsonFile.open(jsonpath, std::ios::out | std::ios::trunc);
			if (jsonFile.is_open())
			{
				jsonFile << jreport.dump();
				jsonFile.close();
			}
		}


		// and wait a bit and do something useful at the same time
		for (int i=0; i< XML_UPDATE_PERIOD*10 && keep_running; i++)
		{
			if (tcport && g_TCServer.AnyAreClosed())
			{
				if (g_TCServer.Accept())
				{
					std::cerr << "Unrecoverable error, aborting..." << std::endl;
					abort();
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////
// modules & queues

std::shared_ptr<CPacketStream> CReflector::GetStream(char module)
{
	auto it=m_Stream.find(module);
	if (it!=m_Stream.end())
		return it->second;

	return nullptr;
}

bool CReflector::IsStreamOpen(const std::unique_ptr<CDvHeaderPacket> &DvHeader)
{
	for (auto it=m_Stream.begin(); it!=m_Stream.end(); it++)
	{
		if ( (it->second->GetStreamId() == DvHeader->GetStreamId()) && (it->second->IsOpen()) )
			return true;
	}
	return false;
}

char CReflector::GetStreamModule(std::shared_ptr<CPacketStream> stream)
{
	for (auto it=m_Stream.begin(); it!=m_Stream.end(); it++)
	{
		if ( it->second == stream )
			return it->first;
	}
	return ' ';
}

////////////////////////////////////////////////////////////////////////////////////////
// report helpers

void CReflector::JsonReport(nlohmann::json &report)
{
	for (auto &item : g_Configure.GetData().items())
	{
		if (isupper(item.key().at(0)))
			report["Configure"][item.key()] = item.value();
	}

	report["Peers"] = nlohmann::json::array();
	auto peers = GetPeers();
	for (auto pit=peers->cbegin(); pit!=peers->cend(); pit++)
		(*pit)->JsonReport(report);
	ReleasePeers();

	report["Clients"] = nlohmann::json::array();
	auto clients = GetClients();
	for (auto cit=clients->cbegin(); cit!=clients->cend(); cit++)
		(*cit)->JsonReport(report);
	ReleaseClients();

	report["Users"] = nlohmann::json::array();
	auto users = GetUsers();
	for (auto uid=users->begin(); uid!=users->end(); uid++)
		(*uid).JsonReport(report);
	ReleaseUsers();
}

void CReflector::WriteXmlFile(std::ofstream &xmlFile)
{
	// write header
	xmlFile << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << std::endl;

	// software version
	xmlFile << "<Version>" << g_Version << "</Version>" << std::endl;

	CCallsign cs = m_Callsign;
	cs.PatchCallsign(0, "XLX", 3);

	// linked peers
	xmlFile << "<" << cs << "linked peers>" << std::endl;
	// lock
	CPeers *peers = GetPeers();
	// iterate on peers
	for ( auto pit=peers->cbegin(); pit!=peers->cend(); pit++ )
	{
		(*pit)->WriteXml(xmlFile);
	}
	// unlock
	ReleasePeers();
	xmlFile << "</" << cs << "linked peers>" << std::endl;

	// linked nodes
	xmlFile << "<" << cs << "linked nodes>" << std::endl;
	// lock
	CClients *clients = GetClients();
	// iterate on clients
	for ( auto cit=clients->cbegin(); cit!=clients->cend(); cit++ )
	{
		if ( (*cit)->IsNode() )
		{
			(*cit)->WriteXml(xmlFile);
		}
	}
	// unlock
	ReleaseClients();
	xmlFile << "</" << cs << "linked nodes>" << std::endl;

	// last heard users
	xmlFile << "<" << cs << "heard users>" << std::endl;
	// lock
	CUsers *users = GetUsers();
	// iterate on users
	for ( auto it=users->begin(); it!=users->end(); it++ )
	{
		it->WriteXml(xmlFile);
	}
	// unlock
	ReleaseUsers();
	xmlFile << "</" << cs << "heard users>" << std::endl;
}

#ifndef NO_DHT
// DHT put() and get()
void CReflector::PutDHTConfig()
{
	const std::string cs(g_Configure.GetString(g_Keys.names.callsign));
	SUrfdConfig1 cfg;
	time(&cfg.timestamp);
	cfg.callsign.assign(cs);
	cfg.ipv4addr.assign(g_Configure.GetString(g_Keys.ip.ipv4address));
	cfg.ipv6addr.assign(g_Configure.GetString(g_Keys.ip.ipv6address));
	cfg.modules.assign(g_Configure.GetString(g_Keys.modules.modules));
	if (g_Configure.GetUnsigned(g_Keys.tc.port))
		cfg.transcodedmods.assign(g_Configure.GetString(g_Keys.tc.modules));
	cfg.url.assign(g_Configure.GetString(g_Keys.names.url));
	cfg.email.assign(g_Configure.GetString(g_Keys.names.email));
	cfg.country.assign(g_Configure.GetString(g_Keys.names.country));
	cfg.sponsor.assign(g_Configure.GetString(g_Keys.names.sponsor));
	std::ostringstream ss;
	ss << g_Version;
	cfg.version.assign(ss.str());
	cfg.almod[toUType(EUrfdAlMod::nxdn)]   = g_Configure.GetAutolinkModule(g_Keys.nxdn.autolinkmod);
	cfg.almod[toUType(EUrfdAlMod::p25)]    = g_Configure.GetAutolinkModule(g_Keys.p25.autolinkmod);
	cfg.almod[toUType(EUrfdAlMod::ysf)]    = g_Configure.GetAutolinkModule(g_Keys.ysf.autolinkmod);
	cfg.ysffreq[toUType(EUrfdTxRx::rx)]    = g_Configure.GetUnsigned(g_Keys.ysf.defaultrxfreq);
	cfg.ysffreq[toUType(EUrfdTxRx::tx)]    = g_Configure.GetUnsigned(g_Keys.ysf.defaulttxfreq);
	cfg.refid[toUType(EUrfdRefId::nxdn)]   = g_Configure.GetUnsigned(g_Keys.nxdn.reflectorid);
	cfg.refid[toUType(EUrfdRefId::p25)]    = g_Configure.GetUnsigned(g_Keys.p25.reflectorid);
	cfg.port[toUType(EUrfdPorts::dcs)]     = (uint16_t)g_Configure.GetUnsigned(g_Keys.dcs.port);
	cfg.port[toUType(EUrfdPorts::dextra)]  = (uint16_t)g_Configure.GetUnsigned(g_Keys.dextra.port);
	cfg.port[toUType(EUrfdPorts::dmrplus)] = (uint16_t)g_Configure.GetUnsigned(g_Keys.dmrplus.port);
	cfg.port[toUType(EUrfdPorts::dplus)]   = (uint16_t)g_Configure.GetUnsigned(g_Keys.dplus.port);
	cfg.port[toUType(EUrfdPorts::m17)]     = (uint16_t)g_Configure.GetUnsigned(g_Keys.m17.port);
	cfg.port[toUType(EUrfdPorts::mmdvm)]   = (uint16_t)g_Configure.GetUnsigned(g_Keys.mmdvm.port);
	cfg.port[toUType(EUrfdPorts::nxdn)]    = (uint16_t)g_Configure.GetUnsigned(g_Keys.nxdn.port);
	cfg.port[toUType(EUrfdPorts::p25)]     = (uint16_t)g_Configure.GetUnsigned(g_Keys.p25.port);
	cfg.port[toUType(EUrfdPorts::urf)]     = (uint16_t)g_Configure.GetUnsigned(g_Keys.urf.port);
	cfg.port[toUType(EUrfdPorts::ysf)]     = (uint16_t)g_Configure.GetUnsigned(g_Keys.ysf.port);
	cfg.g3enabled = g_Configure.GetBoolean(g_Keys.g3.enable);
	for (const auto m : cfg.modules)
		cfg.description[m] = g_Configure.GetString(g_Keys.modules.descriptor[m-'A']);

	auto nv = std::make_shared<dht::Value>(cfg);
	nv->user_type.assign(URFD_CONFIG_1);
	nv->id = toUType(EUrfdValueID::Config);

	node.putSigned(
		refhash,
		nv,
#ifdef DEBUG
		[](bool success){ std::cout << "PutDHTConfig() " << (success ? "successful" : "unsuccessful") << std::endl; },
#else
		[](bool success){ if(! success) std::cout << "PutDHTConfig() unsuccessful" << std::endl; },
#endif
		true
	);
}

void CReflector::GetDHTConfig(const std::string &cs)
{
	static SUrfdConfig1 cfg;
	cfg.timestamp = 0;	// every time this is called, zero the timestamp

	std::cout << "Getting " << cs << " connection info..." << std::endl;

	// we only want the configuration section of the reflector's document
	dht::Where w;
	w.id(toUType(EUrfdValueID::Config));

	node.get(
		dht::InfoHash::get(cs),
		[](const std::shared_ptr<dht::Value> &v) {
			if (0 == v->user_type.compare(URFD_CONFIG_1))
			{
				auto rdat = dht::Value::unpack<SUrfdConfig1>(*v);
				if (rdat.timestamp > cfg.timestamp)
				{
					// the time stamp is the newest so far, so put it in the static cfg struct
					cfg = dht::Value::unpack<SUrfdConfig1>(*v);
				}
			}
			else
			{
				std::cerr << "Get() returned unknown user_type: '" << v->user_type << "'" << std::endl;
			}
			return true;	// check all the values returned
		},
		[](bool success) {
			if (success)
			{
				if (cfg.timestamp)
				{
					// if the get() call was successful and there is a nonzero timestamp, then do the update
					g_GateKeeper.GetInterlinkMap()->Update(cfg.callsign, cfg.modules, cfg.ipv4addr, cfg.ipv6addr, cfg.port[toUType(EUrfdPorts::urf)], cfg.transcodedmods);
					g_GateKeeper.ReleaseInterlinkMap();
				}
				else
				{
					std::cerr << "node.Get() was successful, but the timestamp was zero" << std::endl;
				}
			}
			else
			{
				std::cout << "Get() was unsuccessful" << std::endl;
			}
		},
		{}, // empty filter
		w	// just the configuration section
	);
}

#endif
