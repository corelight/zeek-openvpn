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
	Event(udp_session_done);
	}

OpenVPN_Analyzer::~OpenVPN_Analyzer()
	{
	delete interp;
	if (ssl)
		{
		ssl->Done();
		delete ssl;
		}
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
		ForwardSSL(len, data);
	}

void OpenVPN_Analyzer::ForwardSSL(int len, const u_char* data)
	{
	if (!ssl){
		// We don't care about the direction here.
		ssl = new ssl::SSL_Analyzer(this->Conn());
		}
	ssl->NextStream(len, (const u_char*) data, false);
	}

} // namespace zeek::analyzer::openvpn
