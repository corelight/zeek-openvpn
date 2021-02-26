module OpenVPN;

const ports = { 1194/udp };
const tcp_ports = { };

redef likely_server_ports += { ports, tcp_ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPN, ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNHMAC, ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCP, tcp_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCPHMAC, tcp_ports);
	}
