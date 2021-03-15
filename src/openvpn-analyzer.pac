refine connection OpenVPN_Conn += {

	%member{
		bool seen_control_orig = false;
		bool seen_control_resp = false;
		bool seen_reset_client = false;
		bool seen_handshake = false;
	%}

	function proc_openvpn_message(msg: OpenVPNRecord): bool
		%{
		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V1 )
			{
			if ( !${msg.is_orig} )
				{
				bro_analyzer()->ProtocolViolation(zeek::util::fmt("Should not see client reset in !is_orig"));
				return false;
				}

			seen_reset_client = true;

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_client_v1.tcp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v1.tcp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_client_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_client_v1.tcp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v1.tcp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v1.tcp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(1));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_client_v1.udp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v1.udp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_client_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_client_v1.udp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v1.udp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v1.udp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(1));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V1 )
			{
			if ( ${msg.is_orig} || !seen_reset_client )
				{
				bro_analyzer()->ProtocolViolation(zeek::util::fmt("Should not see server reset in is_orig or haven't seen client reset."));
				return false;
				}

			seen_handshake = true;

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_server_v1.tcp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v1.tcp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_server_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_server_v1.tcp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v1.tcp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v1.tcp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(2));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
		 		}
			else
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_server_v1.udp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v1.udp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_server_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_server_v1.udp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v1.udp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v1.udp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(2));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_SOFT_RESET_V1 )
			{
			if ( !seen_handshake )
				return false;

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_soft_reset_v1.tcp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_soft_reset_v1.tcp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_soft_reset_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_soft_reset_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_soft_reset_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_soft_reset_v1.tcp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_soft_reset_v1.tcp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_soft_reset_v1.tcp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(3));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_soft_reset_v1.udp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_soft_reset_v1.udp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_soft_reset_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_soft_reset_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_soft_reset_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_soft_reset_v1.udp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_soft_reset_v1.udp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_soft_reset_v1.udp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(3));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_V1 )
			{
			if ( !seen_handshake )
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

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_v1.tcp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_v1.tcp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_v1.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_v1.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_v1.tcp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_v1.tcp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_v1.tcp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_v1.tcp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(${msg.rec.control_v1.tcp.ssl_data}.length()));

				rv->Assign(7, zeek::val_mgr->Count(4));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_v1.udp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_v1.udp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_v1.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_v1.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_v1.udp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_v1.udp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_v1.udp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_v1.udp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(${msg.rec.control_v1.udp.ssl_data}.length()));

				rv->Assign(7, zeek::val_mgr->Count(4));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_ACK_V1 )
			{
			if ( !seen_handshake )
				return false;
			if ( !::OpenVPN::ack_message)
				return false;
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::AckMsg);
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

			rv->Assign(5, zeek::val_mgr->Count(5));

			zeek::BifEvent::OpenVPN::enqueue_ack_message(bro_analyzer(),
												         bro_analyzer()->Conn(),
												         ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V1 )
			{
			if ( !seen_handshake )
				return false;

			if (!seen_control_orig || !seen_control_resp)
				return false;

			if (!bro_analyzer()->ProtocolConfirmed())
				{
				bro_analyzer()->ProtocolConfirmation();
				}

			if ( !::OpenVPN::data_message)
				return false;

			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));

			if (${msg.tcp})
				{
				rv->Assign(2, zeek::val_mgr->Count(${msg.rec.data_v1.tcp.payload}.length()));
				}
			else
				{
				rv->Assign(2, zeek::val_mgr->Count(${msg.rec.data_v1.udp.payload}.length()));
				}

			rv->Assign(4, zeek::val_mgr->Count(6));

			zeek::BifEvent::OpenVPN::enqueue_data_message(bro_analyzer(),
												          bro_analyzer()->Conn(),
												          ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V2 )
			{
			if ( !${msg.is_orig} )
				{
				bro_analyzer()->ProtocolViolation(zeek::util::fmt("Should not see client reset in !is_orig"));
				return false;
				}

			seen_reset_client = true;

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_client_v2.tcp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v2.tcp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v2.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_client_v2.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v2.tcp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_client_v2.tcp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v2.tcp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v2.tcp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(7));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_client_v2.udp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v2.udp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_client_v2.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_client_v2.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_client_v2.udp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_client_v2.udp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_client_v2.udp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_client_v2.udp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(7));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_SERVER_V2 )
			{
			if ( ${msg.is_orig} || !seen_reset_client )
				{
				bro_analyzer()->ProtocolViolation(zeek::util::fmt("Should not see server reset in is_orig or haven't seen client reset."));
				return false;
				}

			seen_handshake = true;

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_server_v2.tcp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v2.tcp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v2.tcp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_server_v2.tcp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v2.tcp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_server_v2.tcp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v2.tcp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v2.tcp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(8));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
				rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
				rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));
				rv->Assign<zeek::StringVal>(2, ${msg.rec.control_hard_reset_server_v2.udp.session_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v2.udp.session_id}.begin()));

				auto acks = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
				for ( size_t i=0; i < ${msg.rec.control_hard_reset_server_v2.udp.packet_id_array}->size(); ++i )
					acks->Assign(i, zeek::val_mgr->Count((*${msg.rec.control_hard_reset_server_v2.udp.packet_id_array})[i]));
				rv->Assign(3, acks);

				if (${msg.rec.control_hard_reset_server_v2.udp.packet_id_array_len} > 0)
					{
					rv->Assign<zeek::StringVal>(4, ${msg.rec.control_hard_reset_server_v2.udp.remote_session_id}.length(),
												reinterpret_cast<const char*>(${msg.rec.control_hard_reset_server_v2.udp.remote_session_id}.begin()));
					}

				rv->Assign(5, zeek::val_mgr->Count(${msg.rec.control_hard_reset_server_v2.udp.packet_id}));

				rv->Assign(6, zeek::val_mgr->Count(0));

				rv->Assign(7, zeek::val_mgr->Count(8));

				zeek::BifEvent::OpenVPN::enqueue_control_message(bro_analyzer(),
																 bro_analyzer()->Conn(),
																 ${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V2 )
			{
			if ( !seen_handshake )
				return false;

			if (!seen_control_orig || !seen_control_resp)
				return false;

			if (!bro_analyzer()->ProtocolConfirmed())
				{
				bro_analyzer()->ProtocolConfirmation();
				}

			if ( !::OpenVPN::data_message)
				return false;
				
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OpenVPN::ControlMsg);
			rv->Assign(0, zeek::val_mgr->Count(${msg.opcode}));
			rv->Assign(1, zeek::val_mgr->Count(${msg.key_id}));

			if (${msg.tcp})
				{
				rv->Assign(2, zeek::val_mgr->Count(${msg.rec.data_v2.tcp.payload}.length()));
				rv->Assign<zeek::StringVal>(3, ${msg.rec.data_v2.tcp.peer_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.data_v2.tcp.peer_id}.begin()));
				}
			else
				{
				rv->Assign(2, zeek::val_mgr->Count(${msg.rec.data_v2.udp.payload}.length()));
				rv->Assign<zeek::StringVal>(3, ${msg.rec.data_v2.udp.peer_id}.length(),
											reinterpret_cast<const char*>(${msg.rec.data_v2.udp.peer_id}.begin()));
				}

			rv->Assign(4, zeek::val_mgr->Count(9));

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
