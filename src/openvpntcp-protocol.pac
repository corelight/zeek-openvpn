type OpenVPNPDU(is_orig: bool) = record {
	records: OpenVPNRecordArray(is_orig)[] &transient;
};

type OpenVPNRecordArray(is_orig: bool) = record {
	records: OpenVPNRecord(is_orig, false, true)[] &transient;
};
