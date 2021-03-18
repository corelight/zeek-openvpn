module OpenVPN;

const ports = { 1194/udp };
const tcp_ports = { 443/tcp };

redef likely_server_ports += { ports, tcp_ports };

export {
	## Set to true to disable the analyzer after the protocol is confirmed.
	## This helps reduce processing if you will not look at all of the OpenVPN
	## traffic.
	option disable_analyzer_after_detection = F;

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
	if ( atype == Analyzer::ANALYZER_OPENVPN_UDP || atype == Analyzer::ANALYZER_OPENVPN_UDP_HMAC || atype == Analyzer::ANALYZER_OPENVPN_TCP || atype == Analyzer::ANALYZER_OPENVPN_TCP_HMAC )
		{
		c$openvpn$analyzer_id = aid;
		}
	}

event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::DataMsg)
	{
	if (disable_analyzer_after_detection == T && c?$openvpn && c$openvpn?$analyzer_id)
		{
		disable_analyzer(c$id, c$openvpn$analyzer_id);
		delete c$openvpn$analyzer_id;
		}
	}
