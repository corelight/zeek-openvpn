# @TEST-EXEC: zeek -C -r $TRACES/openvpn-tcp-tls-auth.pcapng %INPUT >openvpn.out
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log

@load zeek/openvpn

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat(msg); }
event OpenVPN::ack_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat(msg); }
event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat(msg); }