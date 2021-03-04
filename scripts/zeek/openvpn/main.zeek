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

function set_session(c: connection)
	{
	if ( ! c?$openvpn )
		c$openvpn = [];
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	set_session(c);
	if ( atype == Analyzer::ANALYZER_OPENVPN || atype == Analyzer::ANALYZER_OPENVPNHMAC || atype == Analyzer::ANALYZER_OPENVPNTCP || atype == Analyzer::ANALYZER_OPENVPNTCPHMAC )
		{
		c$openvpn$analyzer_id = aid;
		}
	}

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) &priority=5
	{
	set_session(c);
	msg$msg_type_str = OpenVPN::msg_types[msg$msg_type];
	}

event OpenVPN::ack_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) &priority=5
	{
	set_session(c);
	msg$msg_type_str = OpenVPN::msg_types[msg$msg_type];
	}

event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) &priority=5
	{
	set_session(c);
	msg$msg_type_str = OpenVPN::msg_types[msg$msg_type];
	}

#event zeek_init() &priority=5
#	{
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPN, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNHMAC, ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCP, tcp_ports);
#	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPNTCPHMAC, tcp_ports);
#	}