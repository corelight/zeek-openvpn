#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/ssl/SSL.h"

#include "events.bif.h"
#include "types.bif.h"
#include "openvpntcp_pac.h"

namespace binpac  {
	namespace OpenVPNTCP {
		class OpenVPN_Conn;
	}
}

namespace analyzer::openvpn::tcp {

class OpenVPN_Analyzer final : public ::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit OpenVPN_Analyzer(Connection* conn);
	~OpenVPN_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;
	void ForwardSSLDataTCP(int len, const u_char* data, bool orig);

	static ::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new OpenVPN_Analyzer(conn); }

protected:
	bool had_gap;
	binpac::OpenVPNTCP::OpenVPN_Conn* interp;
	analyzer::ssl::SSL_Analyzer *ssl = nullptr;
	// Used for limited UDP tracking
	uint64_t orig_seq = 0;
	uint64_t resp_seq = 0;
};

} // namespace zeek::analyzer::openvpn::tcp
