
#pragma once

#include <plugin/Plugin.h>
#include <analyzer/Component.h>
#include "OpenVPN.h"
#include "OpenVPNHMAC.h"
#include "OpenVPNTCP.h"
#include "OpenVPNTCPHMAC.h"

namespace plugin {
namespace zeek_openvpn {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}
