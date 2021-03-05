# @TEST-EXEC: zeek -C -r $TRACES/openvpn_udp_tls-auth.pcapng %INPUT >openvpn.out
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log

@load zeek/openvpn

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg) { print cat(msg); }
event OpenVPN::ack_message(c: connection, is_orig: bool, msg: OpenVPN::AckMsg) { print cat(msg); }
event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::DataMsg) { print cat(msg); }