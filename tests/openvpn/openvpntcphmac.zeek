# @TEST-EXEC: zeek -C -r $TRACES/openvpn-tcp-tls-auth.pcap %INPUT >openvpn.out
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log

@load zeek/openvpn

event openvpn_control_hard_reset_client_v1_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_control_hard_reset_client_v1_message: ", msg); }
event openvpn_control_hard_reset_server_v1_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_control_hard_reset_server_v1_message: ", msg); }
event openvpn_control_soft_reset_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_control_soft_reset_message: ", msg); }
event openvpn_control_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_control_message: ", msg); }
event openvpn_ack_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_ack message: ", msg); }
event openvpn_data1_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_data1 message: ", msg); }
event openvpn_control_hard_reset_client_v2_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_control_hard_reset_client_v2_message: ", msg); }
event openvpn_control_hard_reset_server_v2_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_control_hard_reset_server_v2_message: ", msg); }
event openvpn_data2_message(c: connection, is_orig: bool, msg: OpenVPN::ParsedMsg) { print cat("openvpn_data2 message: ", msg); }