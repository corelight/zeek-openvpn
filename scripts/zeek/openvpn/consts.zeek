module OpenVPN;

export {
	const msg_types = {
		[1] = "P_CONTROL_HARD_RESET_CLIENT_V1",
		[2] = "P_CONTROL_HARD_RESET_SERVER_V1",
		[3] = "P_CONTROL_SOFT_RESET_V1",
		[4] = "P_CONTROL_V1",
		[5] = "P_ACK_V1",
		[6] = "P_DATA_V1",
		[7] = "P_CONTROL_HARD_RESET_CLIENT_V2",
		[8] = "P_CONTROL_HARD_RESET_SERVER_V2",
		[9] = "P_DATA_V2",
	} &default = function(n: count): string { return fmt("unknown-msg-type-%d", n); };
}