refine connection OpenVPN_Conn += {

	function proc_openvpn_message(msg: OpenVPNRecord): bool
		%{
		if ( ${msg.opcode} == P_CONTROL_HARD_RESET_CLIENT_V1 )
			{
			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				if (${msg.rec.control_hard_reset_client_v1.tcp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv =  new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				if (${msg.rec.control_hard_reset_client_v1.udp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv =  new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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
				if (${msg.rec.control_hard_reset_server_v1.tcp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
		 		}
			else
				{
				if (${msg.rec.control_hard_reset_server_v1.udp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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
				if (${msg.rec.control_soft_reset_v1.tcp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				if (${msg.rec.control_soft_reset_v1.udp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_CONTROL_V1 )
			{
			if (!bro_analyzer()->ProtocolConfirmed())
				{
				bro_analyzer()->ProtocolConfirmation();
				}

			if ( !::OpenVPN::control_message)
				return false;

			if (${msg.tcp})
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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
			auto rv = new RecordVal(BifType::Record::OpenVPN::AckMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));
			rv->Assign(2, new StringVal(${msg.rec.ack_v1.session_id}.length(), (const char*)${msg.rec.ack_v1.session_id}.data()));

			auto acks = new VectorVal(index_vec);
			for ( size_t i=0; i < ${msg.rec.ack_v1.packet_id_array}->size(); ++i )
				acks->Assign(i, val_mgr->GetCount((*${msg.rec.ack_v1.packet_id_array})[i]));
			rv->Assign(3, acks);

			rv->Assign(4, new StringVal(${msg.rec.ack_v1.remote_session_id}.length(), (const char*)${msg.rec.ack_v1.remote_session_id}.data()));

			BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
									   			        bro_analyzer()->Conn(),
									   			        ${msg.is_orig}, std::move(rv));
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V1 )
			{
			if ( !::OpenVPN::data_message)
				return false;

			auto rv = new RecordVal(BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));

			if (${msg.tcp})
				{
				rv->Assign(2, val_mgr->GetCount(${msg.rec.data_v1.tcp.payload}.length()));
				}
			else
				{
				rv->Assign(2, val_mgr->GetCount(${msg.rec.data_v1.udp.payload}.length()));
				}

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
				if (${msg.rec.control_hard_reset_client_v2.tcp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("client reset should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				if (${msg.rec.control_hard_reset_client_v2.udp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("client reset should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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
				if (${msg.rec.control_hard_reset_server_v2.tcp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			else
				{
				if (${msg.rec.control_hard_reset_server_v2.udp.ssl_data}.length() != 0)
					{
					bro_analyzer()->ProtocolViolation(fmt("should not have ssl_data."));
					return false;
					}

				if (!bro_analyzer()->ProtocolConfirmed())
					{
					bro_analyzer()->ProtocolConfirmation();
					}

				auto rv = new RecordVal(BifType::Record::OpenVPN::ControlMsg);
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

				BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
															bro_analyzer()->Conn(),
															${msg.is_orig}, std::move(rv));
				}
			return true;
			}

		if ( ${msg.opcode} == P_DATA_V2 )
			{
			if ( !::OpenVPN::data_message)
				return false;
				
			auto rv = new RecordVal(BifType::Record::OpenVPN::DataMsg);
			rv->Assign(0, val_mgr->GetCount(${msg.opcode}));
			rv->Assign(1, val_mgr->GetCount(${msg.key_id}));

			if (${msg.tcp})
				{
				rv->Assign(2, val_mgr->GetCount(${msg.rec.data_v2.tcp.payload}.length()));
				rv->Assign(3, new StringVal(${msg.rec.data_v2.tcp.peer_id}.length(), (const char*)${msg.rec.data_v2.tcp.peer_id}.data()));
				}
			else
				{
				rv->Assign(2, val_mgr->GetCount(${msg.rec.data_v2.udp.payload}.length()));
				rv->Assign(3, new StringVal(${msg.rec.data_v2.udp.peer_id}.length(), (const char*)${msg.rec.data_v2.udp.peer_id}.data()));
				}

			BifEvent::OpenVPN::generate_control_message(bro_analyzer(),
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
