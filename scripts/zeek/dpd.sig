signature dpd_openvpn_udp_req {
  ip-proto == udp
  payload /\x38.{13}/
  enable "openvpn"
}

signature dpd_openvpn_udp_resp {
  ip-proto == udp
  payload /\x40.{13}/
  enable "openvpn"
}

signature dpd_openvpn_tcp_req {
  ip-proto == tcp
  payload /..\x38.{13}/
  enable "openvpn"
}

signature dpd_openvpn_tcp_resp {
  ip-proto == tcp
  payload /..\x40.{13}/
  enable "openvpn"
}
