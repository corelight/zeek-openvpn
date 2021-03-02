module OpenVPN;

const ports = { 1194/udp };
const tcp_ports = { 443/tcp };

redef likely_server_ports += { ports, tcp_ports };

export {
	## The record type which contains OpenVPN info.
	type Info: record {
		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id:      count            &optional;
	};
}

redef record connection += {
	openvpn: Info &optional;
};

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_OPENVPN || atype == Analyzer::ANALYZER_OPENVPNHMAC || atype == Analyzer::ANALYZER_OPENVPNTCP || atype == Analyzer::ANALYZER_OPENVPNTCPHMAC )
		{
		set_session(c);
		c$openvpn$analyzer_id = aid;
		}
	}

#event zeek_init() &priority=5
#	{
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPN, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNHMAC, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCP, tcp_ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCPHMAC, tcp_ports);
#	}

event OpenVPN::message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) &priority=5
	{
	msg$msg_type_str = OpenVPN::msg_types[msg$msg_type];
	}