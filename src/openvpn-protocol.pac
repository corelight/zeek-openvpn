type OpenVPNPDU(is_orig: bool) = record {
	records: OpenVPNRecord(is_orig, false, false)[] &transient;
};


refine connection OpenVPN_Conn += {
	function forward_ssl_udp(ssl_data: bytestring, is_orig: bool, packet_id: uint32) : bool
		%{
		reinterpret_cast<analyzer::openvpn::OpenVPN_Analyzer *>(bro_analyzer())->ForwardSSLDataUDP(ssl_data.length(), reinterpret_cast<const u_char*>(ssl_data.data()), is_orig, packet_id);
		return true;
		%}

	function forward_ssl_tcp(ssl_data: bytestring, is_orig: bool) : bool
		%{
		return true;
		%}
};
