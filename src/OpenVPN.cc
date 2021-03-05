#include "OpenVPN.h"

#include <zeek/Reporter.h>

#include "events.bif.h"

namespace analyzer::openvpn {

OpenVPN_Analyzer::OpenVPN_Analyzer(Connection* c)
	: ::analyzer::Analyzer("OpenVPN", c)
	{
	interp = new binpac::OpenVPN::OpenVPN_Conn(this);
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

void OpenVPN_Analyzer::ForwardSSLDataUDP(int len, const u_char* data, bool orig, uint32_t packet_id)
	{
#if ZEEK_VERSION_NUMBER >= 10100
	// This will check if sequences are in order and stop sending if not.
	if (orig)
		{
		if (orig_seq == 0)
			{
			orig_seq = packet_id;
			}
		else
			{
			if (packet_id == orig_seq+1)
				{
				orig_seq = packet_id;
				}
			else
				{
				return;
				}
			}
		}
	else
		{
		if (resp_seq == 0)
			{
			resp_seq = packet_id;
			}
		else
			{
			if (packet_id == resp_seq+1)
				{
				resp_seq = packet_id;
				}
			else
				{
				return;
				}
			}
		}

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
#endif
	}
} // namespace zeek::analyzer::openvpn
