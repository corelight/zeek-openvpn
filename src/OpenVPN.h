#pragma once

#include "zeek/analyzer/protocol/udp/UDP.h"

#include "events.bif.h"
#include "types.bif.h"
#include "openvpn_pac.h"

namespace binpac  {
	namespace OpenVPN {
		class OpenVPN_Conn;
	}
}

namespace analyzer::openvpn {

class OpenVPN_Analyzer final : public ::analyzer::Analyzer {
public:
	explicit OpenVPN_Analyzer(Connection* conn);
	~OpenVPN_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static ::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new OpenVPN_Analyzer(conn); }

protected:
	binpac::OpenVPN::OpenVPN_Conn* interp;
};

} // namespace zeek::analyzer::openvpn
