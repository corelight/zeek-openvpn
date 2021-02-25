module OpenVPN;
export {
	type OpenVPN::ControlMsg: record {
		## Opcode
		opcode					:	count;
		## Key ID
		key_id					:	count;
		## Session ID
		session_id	    		: 	string;
		## Packet id ack array
		packet_id_ack_array		:	vector of count;
		## Remote session ID
		remote_session_id		:	string;
		## Packet ID
		packet_id				:	count;
		## The SSL data
		ssl_data				:	string;
		## The amount of data
		data_len				:	count;
	};

	type OpenVPN::DataMsg: record {
		## Opcode
		opcode					:	count;
		## Key ID
		key_id					:	count;
		## Peer ID
		peer_id		    		: 	string;
		## The amount of data
		data_len				:	count;
	};
}

