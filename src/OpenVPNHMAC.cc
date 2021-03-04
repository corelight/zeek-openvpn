#include "OpenVPNHMAC.h"

#include <zeek/Reporter.h>

#include "events.bif.h"

namespace analyzer::openvpn::hmac {

OpenVPN_Analyzer::OpenVPN_Analyzer(Connection* c)
	: ::analyzer::Analyzer("OpenVPNHMAC", c)
	{
	interp = new binpac::OpenVPNHMAC::OpenVPN_Conn(this);
	ssl = 0;
	}

void OpenVPN_Analyzer::Done()
	{
	Analyzer::Done();
	if ( ssl )
		{
//		ssl->Done();
		}
	Event(udp_session_done);
	}

OpenVPN_Analyzer::~OpenVPN_Analyzer()
	{
	delete interp;
	}

void OpenVPN_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                     uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

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

void OpenVPN_Analyzer::ForwardSSLDataUDP(int len, const u_char* data, bool orig, uint32_t packet_id)
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
			ssl->DeliverPacket(len, data, orig, packet_id, 0, 0);
			}

		// If there was a client hello - let's confirm this as OpenVPN
		if ( ! ProtocolConfirmed() && ssl->ProtocolConfirmed() )
			ProtocolConfirmation();
	}

} // namespace zeek::analyzer::openvpn::hmac
