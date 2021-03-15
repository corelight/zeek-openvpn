
#include "Plugin.h"

namespace plugin { namespace zeek_openvpn { Plugin plugin; } }

using namespace plugin::zeek_openvpn;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::analyzer::Component("OpenVPN", ::analyzer::openvpn::OpenVPN_Analyzer::Instantiate));
	AddComponent(new ::analyzer::Component("OpenVPNHMAC", ::analyzer::openvpn::hmac::OpenVPN_Analyzer::Instantiate));
	AddComponent(new ::analyzer::Component("OpenVPNTCP", ::analyzer::openvpn::tcp::OpenVPN_Analyzer::Instantiate));
	AddComponent(new ::analyzer::Component("OpenVPNTCPHMAC", ::analyzer::openvpn::tcp::hmac::OpenVPN_Analyzer::Instantiate));
	zeek::plugin::Configuration config;
	config.name = "zeek::openvpn";
	config.description = "A Zeek OpenVPN Protocol Analyzer";
	config.version.major = 0;
	config.version.minor = 0;
	config.version.patch = 8;
	return config;
	}
