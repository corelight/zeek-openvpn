# @TEST-EXEC: zeek -C -r $TRACES/openvpn_udp_tls-auth.pcapng %INPUT >openvpn.out
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log

@load zeek/openvpn

event OpenVPN::message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat(msg); }