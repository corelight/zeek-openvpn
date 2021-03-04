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
			if (${msg.tcp})
				{
				auto rv =  new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_client_v1.tcp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v1.tcp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_client_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_client_v1.tcp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v1.tcp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v1.tcp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v1.tcp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(1));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv =  new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_client_v1.udp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v1.udp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_client_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_client_v1.udp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v1.udp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v1.udp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v1.udp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(1));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			if (${msg.tcp})
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_server_v1.tcp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v1.tcp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_server_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_server_v1.tcp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v1.tcp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v1.tcp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v1.tcp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(2));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
		 		}
			else
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_server_v1.udp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v1.udp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_server_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_server_v1.udp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v1.udp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v1.udp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v1.udp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(2));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_SOFT_RESET_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			if (${msg.tcp})
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_soft_reset_v1.tcp.session_id}.length(), (const char*)${msg.rec.control_soft_reset_v1.tcp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_soft_reset_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_soft_reset_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_soft_reset_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_soft_reset_v1.tcp.remote_session_id}.length(), (const char*)${msg.rec.control_soft_reset_v1.tcp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_soft_reset_v1.tcp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_soft_reset_v1.tcp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(3));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_soft_reset_v1.udp.session_id}.length(), (const char*)${msg.rec.control_soft_reset_v1.udp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_soft_reset_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_soft_reset_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_soft_reset_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_soft_reset_v1.udp.remote_session_id}.length(), (const char*)${msg.rec.control_soft_reset_v1.udp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_soft_reset_v1.udp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_soft_reset_v1.udp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(3));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_V1 )
			{
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

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_v1.tcp.session_id}.length(), (const char*)${msg.rec.control_v1.tcp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_v1.tcp.remote_session_id}.length(), (const char*)${msg.rec.control_v1.tcp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_v1.tcp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_v1.tcp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(4));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_v1.udp.session_id}.length(), (const char*)${msg.rec.control_v1.udp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_v1.udp.remote_session_id}.length(), (const char*)${msg.rec.control_v1.udp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_v1.udp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_v1.udp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(4));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_ACK_V1 )
			{
			if ( !::OpenVPN::ack_message)
				return false;
			auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.ack_v1.session_id}.length(), (const char*)${msg.rec.ack_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.ack_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.ack_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			rv->Assign(4, new StringVal(${msg.rec.ack_v1.remote_session_id}.length(), (const char*)${msg.rec.ack_v1.remote_session_id}.data()));

			rv->Assign(6, val_mgr->GetCount(0));

			rv->Assign(8, val_mgr->GetCount(5));

			BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
									   			        bro_analyzer()->Conn(),
									   			        ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V1 )
			{
			if (seen_control_orig && seen_control_resp)
				{
				bro_analyzer()->ProtocolConfirmation();
				}

			if ( !::OpenVPN::data_message)
				return false;

			auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));

			if (${msg.tcp})
				{
				rv->Assign(6, val_mgr->GetCount(${msg.rec.data_v1.tcp.payload}.length()));
				}
			else
				{
				rv->Assign(6, val_mgr->GetCount(${msg.rec.data_v1.udp.payload}.length()));
				}

			rv->Assign(8, val_mgr->GetCount(6));

			BifEvent::OpenVPN::generate_data_message(bro_analyzer(),
									   		   	     bro_analyzer()->Conn(),
									   			     ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V2 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			if (${msg.tcp})
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_client_v2.tcp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v2.tcp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v2.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_client_v2.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v2.tcp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_client_v2.tcp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v2.tcp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v2.tcp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v2.tcp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(7));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_client_v2.udp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v2.udp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v2.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_client_v2.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v2.udp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_client_v2.udp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_client_v2.udp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v2.udp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_client_v2.udp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(7));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V2 )
			{
			if ( !::OpenVPN::control_message)
				return false;
			if (${msg.tcp})
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_server_v2.tcp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v2.tcp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v2.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_server_v2.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v2.tcp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_server_v2.tcp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v2.tcp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v2.tcp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v2.tcp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(8));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ParsedMsg);
				rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
				rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
				rv->Assign(2, new StringVal(${msg.rec.control_hard_reset_server_v2.udp.session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v2.udp.session_id}.data()));

				auto acks = new VectorVal(index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v2.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, val_mgr->GetCount((*${msg.rec.control_hard_reset_server_v2.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v2.udp.packet_id_array_len} > 0)
					{
					rv->Assign(4, new StringVal(${msg.rec.control_hard_reset_server_v2.udp.remote_session_id}.length(), (const char*)${msg.rec.control_hard_reset_server_v2.udp.remote_session_id}.data()));
					}

				rv->Assign(5, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v2.udp.packet_id}));

				rv->Assign(6, val_mgr->GetCount(${msg.rec.control_hard_reset_server_v2.udp.ssl_data}.length()));

				rv->Assign(8, val_mgr->GetCount(8));

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V2 )
			{
			if (seen_control_orig && seen_control_resp)
				{
				bro_analyzer()->ProtocolConfirmation();
				}

			if ( !::OpenVPN::data_message)
				return false;
				
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ParsedMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));

			if (${msg.tcp})
				{
				rv->Assign(6, val_mgr->GetCount(${msg.rec.data_v2.tcp.payload}.length()));
				rv->Assign(7, new StringVal(${msg.rec.data_v2.tcp.peer_id}.length(), (const char*)${msg.rec.data_v2.tcp.peer_id}.data()));
				}
			else
				{
				rv->Assign(6, val_mgr->GetCount(${msg.rec.data_v2.udp.payload}.length()));
				rv->Assign(7, new StringVal(${msg.rec.data_v2.udp.peer_id}.length(), (const char*)${msg.rec.data_v2.udp.peer_id}.data()));
				}

			rv->Assign(8, zeek::val_mgr->Count(9));

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
			delete ssl;
			ssl = 0;
			}
	%}

	function forward_ssl_tcp(ssl_data: bytestring, is_orig: bool) : bool
		%{
		if ( ! ssl )
			{
			ssl = new analyzer::ssl::SSL_Analyzer(bro_analyzer()->Conn());
			}
		if ( ssl )
			{
			ssl->DeliverStream(${ssl_data}.length(), ${ssl_data}.begin(), is_orig);
			}
		return true;
		%}

	function forward_ssl_udp(ssl_data: bytestring, is_orig: bool) : bool
		%{
		if ( ! ssl )
			{
			ssl = new analyzer::ssl::SSL_Analyzer(bro_analyzer()->Conn());
			}
		if ( ssl )
			{
			ssl->DeliverPacket(${ssl_data}.length(), ${ssl_data}.begin(), is_orig, 0, 0, 0);
			}
		return true;
		%}

};