signature dpd_openvpn_udp_client {
  ip-proto == udp
  payload /^\x38.{8}\x00\x00\x00\x00\x00/
  enable "openvpn_udp"
}

signature dpd_openvpnhmac_udp_client {
  ip-proto == udp
  payload /^\x38.{36}\x00\x00\x00\x00\x00/
  enable "openvpn_udp_hmac"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{8}\x00\x00\x00\x00\x00/
  enable "openvpn_tcp"
}

signature dpd_openvpnhmac_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{36}\x00\x00\x00\x00\x00/
  enable "openvpn_tcp_hmac"
}