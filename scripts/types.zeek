module OpenVPN;
export {
	type ControlMsg: record {
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
		## The amount of data
		data_len				:	count;
		## The type of parsed OpenVPN message.
		msg_type				:	count;
	};

	type AckMsg: record {
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
		## The type of parsed OpenVPN message.
		msg_type				:	count;
	};

	type DataMsg: record {
		## Opcode
		opcode					:	count;
		## Key ID
		key_id					:	count;
		## The amount of data
		data_len				:	count;
		## Peer ID
		peer_id		    		: 	string &optional;
		## The type of parsed OpenVPN message.
		msg_type				:	count;
	};

}

