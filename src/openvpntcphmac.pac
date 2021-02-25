
%include binpac.pac
%include bro.pac

%extern{
	#include "types.bif.h"
	#include "events.bif.h"
	#include "OpenVPNTCPHMAC.h"
%}

analyzer OpenVPNTCPHMAC withcontext {
	connection: OpenVPN_Conn;
	flow:       OpenVPN_Flow;
};

connection OpenVPN_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = OpenVPN_Flow(true);
	downflow = OpenVPN_Flow(false);
};

%include openvpntcphmac-protocol.pac

flow OpenVPN_Flow(is_orig: bool) {
	datagram = OpenVPNPDU(is_orig) withcontext(connection, this);
};

%include openvpntcphmac-analyzer.pac