
%include binpac.pac
%include bro.pac

%extern{
	#include "types.bif.h"
	#include "events.bif.h"
	#include "OpenVPN.h"
%}

analyzer OpenVPN withcontext {
	connection: OpenVPN_Conn;
	flow:       OpenVPN_Flow;
};

connection OpenVPN_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = OpenVPN_Flow(true);
	downflow = OpenVPN_Flow(false);
};

%include openvpn-protocol.pac

flow OpenVPN_Flow(is_orig: bool) {
	datagram = OpenVPNPDU(is_orig) withcontext(connection, this);
};

%include openvpn-analyzer.pac