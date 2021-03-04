%extern{
#include "analyzer/Manager.h"
%}


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

type OpenVPNRecord(is_orig: bool, hmac: bool, tcp: bool) = record {
	tcpfields: case tcp of {
			true	-> packet_length : uint16;
			false	-> no_key : empty;
	};
	MessageType : uint8;
	rec: OpenVPNData(this) &requires(opcode, key_id);
} &let {
	opcode : uint8 = (MessageType >> 3);  # The high 5 bits
			key_id : uint8  = (MessageType & 0x07);  # The low 3 bits
} &byteorder = bigendian;

type OpenVPNData(rec: OpenVPNRecord) = case rec.opcode of {
		P_CONTROL_HARD_RESET_CLIENT_V1 	-> control_hard_reset_client_v1: 	Control(rec, false);
		P_CONTROL_HARD_RESET_SERVER_V1 	-> control_hard_reset_server_v1: 	Control(rec, false);
		P_CONTROL_SOFT_RESET_V1 		-> control_soft_reset_v1: 			Control(rec, false);
		P_CONTROL_V1 					-> control_v1: 						Control(rec, true);
		P_ACK_V1 						-> ack_v1: 							AckV1(rec);
		P_DATA_V1 						-> data_v1: 						DataV1(rec);
		P_CONTROL_HARD_RESET_CLIENT_V2 	-> control_hard_reset_client_v2: 	Control(rec, false);
		P_CONTROL_HARD_RESET_SERVER_V2 	-> control_hard_reset_server_v2: 	Control(rec, false);
		P_DATA_V2 						-> data_v2: 						DataV2(rec);
		default 						-> unknown: 						bytestring &restofdata &transient;
};

type HMACInfo = record {
		hmac : bytestring &length=20;
		packet_id : uint32;
		net_time  : bytestring &length=4;
};

type Control(rec: OpenVPNRecord, control_v1: bool) = record {
	control_data: case rec.tcp of {
			true	-> tcp : ControlTCP(rec, control_v1);
			false	-> udp : ControlUDP(rec, control_v1);
	};
};

type ControlUDP(rec: OpenVPNRecord, control_v1: bool) = record {
	session_id : bytestring &length=8;
	hmac_present: case rec.hmac of {
			true	-> hmac : HMACInfo;
			false	-> no_key : empty;
	};
	packet_id_array_len : uint8;
	packet_id_array : uint32[packet_id_array_len];
	rs: case packet_id_array_len of {
			0 -> nothing: bytestring &length=0;
			default -> remote_session_id: bytestring &length=8;
	};
	packet_id : uint32;
	ssl_data : bytestring &restofdata;
} &let {
	ssl_data_forwarded : bool = $context.connection.forward_ssl_udp(ssl_data, rec.is_orig) &if(control_v1 == true);
};

type ControlTCP(rec: OpenVPNRecord, control_v1: bool) = record {
	session_id : bytestring &length=8;
	hmac_present: case rec.hmac of {
			true	-> hmac : HMACInfo;
			false	-> no_key : empty;
	};
	packet_id_array_len : uint8;
	packet_id_array : uint32[packet_id_array_len];
	rs: case packet_id_array_len of {
			0 -> nothing: bytestring &length=0;
			default -> remote_session_id: bytestring &length=8;
	};
	packet_id : uint32;
	ssl_data : bytestring &restofdata;
} &let {
	ssl_data_forwarded : bool = $context.connection.forward_ssl_tcp(ssl_data, rec.is_orig) &if(control_v1 == true);
} &length=rec.packet_length-1;

type AckV1(rec: OpenVPNRecord) = record {
	session_id : bytestring &length=8;
	hmac_present: case rec.hmac of {
			false	-> no_key : empty;
			true	-> hmac : HMACInfo;
	};
	packet_id_array_len : uint8;
	packet_id_array : uint32[packet_id_array_len];
	remote_session_id: bytestring &length=8;
};

type DataV1(rec: OpenVPNRecord) = record {
	data: case rec.tcp of {
		true	-> tcp : DataV1TCP(rec);
		false	-> udp : DataV1UDP(rec);
	};
};

type DataV1TCP(rec: OpenVPNRecord) = record {
	payload 		: bytestring &restofdata;
} &length=rec.packet_length-1;

type DataV1UDP(rec: OpenVPNRecord) = record {
	payload 		: bytestring &restofdata;
};

type DataV2(rec: OpenVPNRecord) = record {
	data: case rec.tcp of {
		true	-> tcp : DataV2TCP(rec);
		false	-> udp : DataV2UDP(rec);
	};
};

type DataV2TCP(rec: OpenVPNRecord) = record {
	peer_id       	: bytestring &length=3;
	payload 		: bytestring &restofdata;
} &length=rec.packet_length-1;

type DataV2UDP(rec: OpenVPNRecord) = record {
	peer_id       	: bytestring &length=3;
	payload 		: bytestring &restofdata;
};