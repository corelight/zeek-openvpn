type OpenVPNPDU(is_orig: bool) = record {
	records: OpenVPNRecord(is_orig, false, false)[] &transient;
};
