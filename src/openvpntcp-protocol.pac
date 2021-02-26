enum Openvpn_Opcode {
	P_CONTROL_HARD_RESET_CLIENT_V1	= 0x01,
	P_CONTROL_HARD_RESET_SERVER_V1	= 0x02,
	P_CONTROL_SOFT_RESET_V1		= 0x03,
	P_CONTROL_V1			= 0x04,
	P_ACK_V1			= 0x05,
	P_DATA_V1			= 0x06,
	P_CONTROL_HARD_RESET_CLIENT_V2	= 0x07,
	P_CONTROL_HARD_RESET_SERVER_V2	= 0x08,
	P_DATA_V2			= 0x09,
};

type OpenVPNPDU(is_orig: bool) = record {
	records: OpenVPNRecord(is_orig) &transient;
};

type OpenVPNRecord(is_orig: bool) = record {
	packet_length : uint16;
	MessageType : uint8;
	rec: OpenVPNData(this) &requires(opcode, key_id);
} &let {
	opcode : uint8 = (MessageType >> 3);  # The high 5 bits
	key_id : uint8  = (MessageType & 0x07);  # The low 3 bits
} &byteorder = bigendian;

type OpenVPNData(rec: OpenVPNRecord) = case rec.opcode of {
	P_CONTROL_HARD_RESET_CLIENT_V1 	-> control_hard_reset_client_v1: 	Control(rec);
	P_CONTROL_HARD_RESET_SERVER_V1 	-> control_hard_reset_server_v1: 	Control(rec);
	P_CONTROL_SOFT_RESET_V1 		-> control_soft_reset_v1: 			Control(rec);
	P_CONTROL_V1 					-> control_v1: 						Control(rec);
	P_ACK_V1 						-> ack_v1: 							AckV1(rec);
	P_DATA_V1 						-> data_v1: 						DataV1(rec);
	P_CONTROL_HARD_RESET_CLIENT_V2 	-> control_hard_reset_client_v2: 	Control(rec);
	P_CONTROL_HARD_RESET_SERVER_V2 	-> control_hard_reset_server_v2: 	Control(rec);
	P_DATA_V2 						-> data_v2: 						DataV2(rec);
	default 						-> unknown: 						bytestring &restofdata &transient;
};

type Control(rec: OpenVPNRecord) = record {
	session_id : bytestring &length=8;
	packet_id_array_len : uint8;
	packet_id_array : uint32[packet_id_array_len];
	rs: case  packet_id_array_len of {
		0 -> nothing: bytestring &length=0;
		default -> remote_session_id: bytestring &length=8;
	};
	packet_id : uint32;
	ssl_data : bytestring &restofdata;
};

type AckV1(rec: OpenVPNRecord) = record {
	session_id : bytestring &length=8;
	packet_id_array_len : uint8;
	packet_id_array : uint32[packet_id_array_len];
	remote_session_id: bytestring &length=8;
};

type DataV1(rec: OpenVPNRecord) = record {
	payload 		: bytestring &restofdata;
};

type DataV2(rec: OpenVPNRecord) = record {
	peer_id       	: bytestring &length=3;
	payload 		: bytestring &restofdata;
};
