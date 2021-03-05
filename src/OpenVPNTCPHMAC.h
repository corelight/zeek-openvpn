#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/ssl/SSL.h"

#include "events.bif.h"
#include "types.bif.h"
#include "openvpntcphmac_pac.h"

namespace binpac  {
	namespace OpenVPNTCPHMAC {
		class OpenVPN_Conn;
	}
}

namespace analyzer::openvpn::tcp::hmac {

class OpenVPN_Analyzer final : public ::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit OpenVPN_Analyzer(Connection* conn);
	~OpenVPN_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;
	void ForwardSSLDataTCP(int len, const u_char* data, bool orig);

	static ::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new OpenVPN_Analyzer(conn); }

protected:
	bool had_gap;
	binpac::OpenVPNTCPHMAC::OpenVPN_Conn* interp;
	analyzer::ssl::SSL_Analyzer *ssl = nullptr;
	// Used for limited UDP tracking
	uint64_t orig_seq = 0;
	uint64_t resp_seq = 0;
};

} // namespace zeek::analyzer::openvpn::tcp
