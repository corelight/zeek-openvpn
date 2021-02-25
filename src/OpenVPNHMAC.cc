#include "OpenVPNHMAC.h"

#include <zeek/Reporter.h>

#include "events.bif.h"

namespace analyzer::openvpn::hmac {

OpenVPN_Analyzer::OpenVPN_Analyzer(Connection* c)
	: ::analyzer::Analyzer("OpenVPNHMAC", c)
	{
	interp = new binpac::OpenVPNHMAC::OpenVPN_Conn(this);
	}

void OpenVPN_Analyzer::Done()
	{
	Analyzer::Done();
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

} // namespace zeek::analyzer::openvpn::hmac
