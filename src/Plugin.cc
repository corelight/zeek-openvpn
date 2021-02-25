
#include "Plugin.h"

namespace plugin { namespace zeek_openvpn { Plugin plugin; } }

using namespace plugin::zeek_openvpn;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::analyzer::Component("OpenVPN", ::analyzer::openvpn::OpenVPN_Analyzer::Instantiate));
	zeek::plugin::Configuration config;
	config.name = "zeek::openvpn";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
