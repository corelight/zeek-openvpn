refine connection OpenVPN_Conn += {

	%member{
		bool seen_control_orig = false;
		bool seen_control_resp = false;
	%}

	function proc_openvpn_message(msg: OpenVPNRecord): bool
		%{
		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;

			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(1));

			zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
													         bro_analyzer()->Conn(),
													         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(2));

			zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
													         bro_analyzer()->Conn(),
													         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_SOFT_RESET_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(3));

			zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
													         bro_analyzer()->Conn(),
													         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			if (${msg.is_orig})
				{
				seen_control_orig = true;
				}
			else
				{
				if (seen_control_orig)
					{
					seen_control_resp = true;
					}
				}

			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(4));

			zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
													         bro_analyzer()->Conn(),
													         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_ACK_V1 )
			{
			if ( !::OpenVPN::ack_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(5));

			zeek::BifEvent::OpenVPN::enqueue_ack_message(bro_analyzer(),
												         bro_analyzer()->Conn(),
												         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V1 )
			{
			if ( !::OpenVPN::data_message)
				return false;
			if (seen_control_orig && seen_control_resp)
				{
				bro_analyzer()->ProtocolConfirmation();
				}
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.data_v1.payload}.length()));

			rv->Assign(9, zeek::val_mgr->Count(6));

			zeek::BifEvent::OpenVPN::enqueue_data_message(bro_analyzer(),
												          bro_analyzer()->Conn(),
												          ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V2 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(7));

			zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
													         bro_analyzer()->Conn(),
													         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V2 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
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

			rv->Assign(9, zeek::val_mgr->Count(8));

			zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
													         bro_analyzer()->Conn(),
													         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V2 )
			{
			if ( !::OpenVPN::data_message)
				return false;
			if (seen_control_orig && seen_control_resp)
				{
				bro_analyzer()->ProtocolConfirmation();
				}
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
			rv->Assign(7, zeek::val_mgr->Count(${msg.rec.data_v2.payload}.length()));
			rv->Assign<zeek::StringVal>(8, ${msg.rec.data_v2.peer_id}.length(),
										reinterpret_cast<const char*>(${msg.rec.data_v2.peer_id}.begin()));

			rv->Assign(9, zeek::val_mgr->Count(9));

			zeek::BifEvent::OpenVPN::enqueue_data_message(bro_analyzer(),
												          bro_analyzer()->Conn(),
												          ${msg.is_orig}, std::move(rv));
			return true;
			}

		return false;
		%}
};

refine typeattr OpenVPNRecord += &let {
	proc: bool = $context.connection.proc_openvpn_message(this);
};

refine connection OpenVPN_Conn += {

	%member{
		analyzer::ssl::SSL_Analyzer *ssl;
	%}

	%init{
		ssl = 0;
	%}

	%cleanup{
		if ( ssl )
			{
			ssl->Done();
			}
	%}

	function forward_ssl(ssl_data: bytestring, is_orig: bool) : bool
		%{
		if ( ! ssl )
			ssl = (analyzer::ssl::SSL_Analyzer *)analyzer_mgr->InstantiateAnalyzer("SSL", bro_analyzer()->Conn());
		if ( ssl )
			{
 			ssl->DeliverData(${ssl_data}.length(), ${ssl_data}.begin(), is_orig, 0, 0, 0);
			}
		return true;
		%}
};