refine flow OpenVPN_Flow += {

	function proc_openvpn_message(msg: OpenVPNRecord): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( !::OpenVPN::message)
			return false;

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V1 )
			{
			auto rv =  new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_client_v1.session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_client_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_client_v1.packet_id_array_len} > 0)
				{
				rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_client_v1.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v1.remote_session_id}.data()));
				}

			rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v1.packet_id}));

			rv->Assign(7, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v1.ssl_data}.length()));

			rv->Assign(9, val_mgr->GetCount(1));

			BifEvent::generate_message(connection()->bro_analyzer(),
			  						   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V1 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_server_v1.session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_server_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_server_v1.packet_id_array_len} > 0)
				{
				rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_server_v1.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v1.remote_session_id}.data()));
				}

			rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v1.packet_id}));

			rv->Assign(7, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v1.ssl_data}.length()));

			rv->Assign(9, val_mgr->GetCount(2));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_SOFT_RESET_V1 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.control_soft_reset_v1.session_id}.length(), (const char*)${msg.rec.control_soft_reset_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.control_soft_reset_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_soft_reset_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_soft_reset_v1.packet_id_array_len} > 0)
				{
				rv->Assign(4, new StringVal(${msg.rec.control_soft_reset_v1.remote_session_id}.length(), (const char*)${msg.rec.control_soft_reset_v1.remote_session_id}.data()));
				}

			rv->Assign(5, val_mgr->GetCount(${msg.rec.control_soft_reset_v1.packet_id}));

			rv->Assign(7, val_mgr->GetCount(${msg.rec.control_soft_reset_v1.ssl_data}.length()));

			rv->Assign(9, val_mgr->GetCount(3));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_V1 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.control_v1.session_id}.length(), (const char*)${msg.rec.control_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.control_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_v1.packet_id_array_len} > 0)
				{
				rv->Assign(4, new StringVal(${msg.rec.control_v1.remote_session_id}.length(), (const char*)${msg.rec.control_v1.remote_session_id}.data()));
				}

			rv->Assign(5, val_mgr->GetCount(${msg.rec.control_v1.packet_id}));

			rv->Assign(6, new StringVal(${msg.rec.control_v1.ssl_data}.length(), (const char*)${msg.rec.control_v1.ssl_data}.data()));

			rv->Assign(7, val_mgr->GetCount(${msg.rec.control_v1.ssl_data}.length()));

			rv->Assign(9, val_mgr->GetCount(4));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_ACK_V1 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.ack_v1.session_id}.length(), (const char*)${msg.rec.ack_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.ack_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.ack_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			rv->Assign(4, new StringVal(${msg.rec.ack_v1.remote_session_id}.length(), (const char*)${msg.rec.ack_v1.remote_session_id}.data()));

			rv->Assign(7, val_mgr->GetCount(0));

			rv->Assign(9, val_mgr->GetCount(5));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V1 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(7, val_mgr->GetCount(${msg.rec.data_v1.payload}.length()));

			rv->Assign(9, zeek::val_mgr->Count(6));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V2 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_client_v2.session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v2.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v2.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_client_v2.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_client_v2.packet_id_array_len} > 0)
				{
				rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_client_v2.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v2.remote_session_id}.data()));
				}

			rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v2.packet_id}));

			rv->Assign(7, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v2.ssl_data}.length()));

			rv->Assign(9, zeek::val_mgr->Count(7));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V2 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_server_v2.session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v2.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v2.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_server_v2.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_server_v2.packet_id_array_len} > 0)
				{
				rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_server_v2.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v2.remote_session_id}.data()));
				}

			rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v2.packet_id}));

			rv->Assign(7, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v2.ssl_data}.length()));

			rv->Assign(9, zeek::val_mgr->Count(8));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V2 )
			{
			auto rv = new RecordVal(BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(7, val_mgr->GetCount(${msg.rec.data_v2.payload}.length()));
			rv->Assign(8, new StringVal(${msg.rec.data_v2.peer_id}.length(), (const char*)${msg.rec.data_v2.peer_id}.data()));
			rv->Assign(9, val_mgr->Count(9));

			BifEvent::generate_message(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), std::move(rv));
			return true;
			}

		return false;
		%}
};

refine typeattr OpenVPNRecord += &let {
	proc: bool = $context.flow.proc_openvpn_message(this);
};
