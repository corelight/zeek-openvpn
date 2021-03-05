#include "OpenVPNTCPHMAC.h"

#include <zeek/Reporter.h>

#include "events.bif.h"

namespace analyzer::openvpn::tcp::hmac {

OpenVPN_Analyzer::OpenVPN_Analyzer(Connection* c)
	: ::analyzer::tcp::TCP_ApplicationAnalyzer("OpenVPNTCPHMAC", c)
	{
	had_gap = false;
	interp = new binpac::OpenVPNTCPHMAC::OpenVPN_Conn(this);
	ssl = 0;
	}

void OpenVPN_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();
	interp->FlowEOF(true);
	interp->FlowEOF(false);
	if ( ssl )
		{
//		ssl->Done();
		}
	}

OpenVPN_Analyzer::~OpenVPN_Analyzer()
	{
	delete interp;
	}

void OpenVPN_Analyzer::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void OpenVPN_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void OpenVPN_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void OpenVPN_Analyzer::ForwardSSLDataTCP(int len, const u_char* data, bool orig)
	{
	if ( !ssl )
		{
		ssl = reinterpret_cast<analyzer::ssl::SSL_Analyzer*>(analyzer_mgr->InstantiateAnalyzer("SSL", Conn()));
		if ( !ssl )
			{
			reporter->InternalError("Could not instantiate SSL Analyzer");
			return;
			}

		AddChildAnalyzer(ssl);
		}

	if ( ssl )
		{
		ssl->DeliverStream(len, data, orig);
		}

	// If there was a client hello - let's confirm this as OpenVPN
	if ( ! ProtocolConfirmed() && ssl->ProtocolConfirmed() )
		ProtocolConfirmation();
	}

} // namespace zeek::analyzer::openvpn::tcp
