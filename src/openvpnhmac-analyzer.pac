refine flow OpenVPN_Flow += {

	function proc_openvpn_message(msg: OpenVPNRecord): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V1 )
			{
			if ( !openvpn_control_hard_reset_client_v1_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_client_v1.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v1.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_client_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_client_v1.packet_id_array_len} > 0)
				{
				rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_client_v1.remote_session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v1.remote_session_id}.begin()));
				}

			rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v1.packet_id}));

			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v1.ssl_data}.length()));

			zeek::BifEvent::enqueue_openvpn_control_hard_reset_client_v1_message(connection()->bro_analyzer(),
																				 connection()->bro_analyzer()->Conn(),
																				 is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V1 )
			{
			if ( !openvpn_control_hard_reset_server_v1_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_server_v1.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v1.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_server_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_server_v1.packet_id_array_len} > 0)
				{
				rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_server_v1.remote_session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v1.remote_session_id}.begin()));
				}

			rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v1.packet_id}));

			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v1.ssl_data}.length()));

			zeek::BifEvent::enqueue_openvpn_control_hard_reset_server_v1_message(connection()->bro_analyzer(),
																				 connection()->bro_analyzer()->Conn(),
																				 is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_SOFT_RESET_V1 )
			{
			if ( !openvpn_control_soft_reset_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.control_soft_reset_v1.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_soft_reset_v1.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.control_soft_reset_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_soft_reset_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_soft_reset_v1.packet_id_array_len} > 0)
				{
				rv->Assign<zeek::StringVal>(4, ${msg.rec.control_soft_reset_v1.remote_session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_soft_reset_v1.remote_session_id}.begin()));
				}

			rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_soft_reset_v1.packet_id}));

			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.control_soft_reset_v1.ssl_data}.length()));

			zeek::BifEvent::enqueue_openvpn_control_soft_reset_message(connection()->bro_analyzer(),
																	   connection()->bro_analyzer()->Conn(),
																	   is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_V1 )
			{
			if ( !openvpn_control_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.control_v1.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_v1.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.control_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_v1.packet_id_array_len} > 0)
				{
				rv->Assign<zeek::StringVal>(4, ${msg.rec.control_v1.remote_session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_v1.remote_session_id}.begin()));
				}

			rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_v1.packet_id}));

			rv->Assign<zeek::StringVal>(6, ${msg.rec.control_v1.ssl_data}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_v1.ssl_data}.begin()));

			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.control_v1.ssl_data}.length()));

			zeek::BifEvent::enqueue_openvpn_control_message(connection()->bro_analyzer(),
															connection()->bro_analyzer()->Conn(),
															is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_ACK_V1 )
			{
			if ( !openvpn_ack_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.ack_v1.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.ack_v1.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.ack_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.ack_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			rv->Assign<zeek::StringVal>(4, ${msg.rec.ack_v1.remote_session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.ack_v1.remote_session_id}.begin()));

			rv->Assign(7, zeek::val_mgr->Count(0));

			zeek::BifEvent::enqueue_openvpn_ack_message(connection()->bro_analyzer(),
														connection()->bro_analyzer()->Conn(),
														is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V1 )
			{
			if ( !openvpn_data1_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign(3, zeek::val_mgr->Count(${msg.rec.data_v1.payload}.length()));

			zeek::BifEvent::enqueue_openvpn_data1_message(connection()->bro_analyzer(),
														  connection()->bro_analyzer()->Conn(),
														  is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V2 )
			{
			if ( !openvpn_control_hard_reset_client_v2_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_client_v2.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v2.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v2.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_client_v2.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_client_v2.packet_id_array_len} > 0)
				{
				rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_client_v2.remote_session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v2.remote_session_id}.begin()));
				}

			rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v2.packet_id}));

			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v2.ssl_data}.length()));

			zeek::BifEvent::enqueue_openvpn_control_hard_reset_client_v2_message(connection()->bro_analyzer(),
																				 connection()->bro_analyzer()->Conn(),
																				 is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V2 )
			{
			if ( !openvpn_control_hard_reset_server_v2_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_server_v2.session_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v2.session_id}.begin()));

			auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
			for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v2.packet_id_array}->size(); ++i )
				acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_server_v2.packet_id_array})[i]));
			rv->Assign(3, acks);

			if (${msg.rec.control_hard_reset_server_v2.packet_id_array_len} > 0)
				{
				rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_server_v2.remote_session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v2.remote_session_id}.begin()));
				}

			rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v2.packet_id}));

			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v2.ssl_data}.length()));

			zeek::BifEvent::enqueue_openvpn_control_hard_reset_server_v2_message(connection()->bro_analyzer(),
																				 connection()->bro_analyzer()->Conn(),
																				 is_orig(), std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V2 )
			{
			if ( !openvpn_data2_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign<zeek::StringVal>(2, ${msg.rec.data_v2.peer_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.data_v2.peer_id}.begin()));
			rv->Assign(3, zeek::val_mgr->Count(${msg.rec.data_v2.payload}.length()));
			zeek::BifEvent::enqueue_openvpn_data2_message(connection()->bro_analyzer(),
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
