
#pragma once

#include <zeek/plugin/Plugin.h>
#include <zeek/analyzer/Component.h>
#include "OpenVPN.h"

namespace plugin {
namespace zeek_openvpn {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}
