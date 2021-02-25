module OpenVPN;

const ports = { 1194/udp, 1195/udp, 1196/udp, 1197/udp, 1198/udp };
const tcp_ports = { 1194/tcp, 1195/tcp, 1196/tcp, 1197/tcp, 1198/tcp };

redef likely_server_ports += { ports, tcp_ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPN, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNHMAC, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCP, tcp_ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCPHMAC, tcp_ports);
	}
