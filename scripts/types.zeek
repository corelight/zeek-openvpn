module OpenVPN;
export {
	type ParsedMsg: record {
		## Opcode
		opcode					:	count;
		## Key ID
		key_id					:	count;
		## Session ID
		session_id	    		: 	string &optional;
		## Packet id ack array
		packet_id_ack_array		:	vector of count &optional;
		## Remote session ID
		remote_session_id		:	string &optional;
		## Packet ID
		packet_id				:	count &optional;
		## The SSL data
		ssl_data				:	string &optional;
		## The amount of data
		data_len				:	count;
		## Peer ID
		peer_id		    		: 	string &optional;
	};
}

