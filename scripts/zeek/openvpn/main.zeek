module OpenVPN;

const ports = { 1194/udp };
const tcp_ports = { 443/tcp };

redef likely_server_ports += { ports, tcp_ports };

#event zeek_init() &priority=5
#	{
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPN, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNHMAC, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCP, tcp_ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCPHMAC, tcp_ports);
#	}

event OpenVPN::message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) &priority=5
	{
	msg$msg_type_str = OpenVPN::msg_types(msg$msg_type);
	}