type OpenVPNPDU(is_orig: bool) = record {
	records: OpenVPNRecord(is_orig, false, true)[] &transient;
};


refine connection OpenVPN_Conn += {
	function forward_ssl_tcp(ssl_data: bytestring, is_orig: bool) : bool
		%{
		reinterpret_cast<analyzer::openvpn::tcp::OpenVPN_Analyzer *>(bro_analyzer())->ForwardSSLDataTCP(ssl_data.length(), reinterpret_cast<const u_char*>(ssl_data.data()), is_orig);
		return true;
		%}

	function forward_ssl_udp(ssl_data: bytestring, is_orig: bool, packet_id: uint32) : bool
		%{
		return true;
		%}
};