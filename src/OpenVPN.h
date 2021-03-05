#pragma once

#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/protocol/ssl/SSL.h"

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
	void ForwardSSLDataTCP(int len, const u_char* data, bool orig);
	void ForwardSSLDataUDP(int len, const u_char* data, bool orig, uint32_t packet_id);

	static ::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new OpenVPN_Analyzer(conn); }

protected:
	binpac::OpenVPN::OpenVPN_Conn* interp;
	analyzer::ssl::SSL_Analyzer *ssl = nullptr;
	// Used for limited UDP tracking
	uint64_t orig_seq = 0;
	uint64_t resp_seq = 0;
};

} // namespace zeek::analyzer::openvpn
