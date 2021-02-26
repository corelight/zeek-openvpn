signature dpd_openvpn_udp_req {
  ip-proto == udp
  payload /\x38.{8}\x00\x00\x00\x00\x00/
  enable "openvpn"
}

signature dpd_openvpn_udp_resp {
  ip-proto == udp
  payload /\x40/
  enable "openvpn"
  requires-reverse-signature dpd_openvpn_udp_req
}

signature dpd_openvpnhmac_udp_req {
  ip-proto == udp
  payload /\x38.{36}\x00\x00\x00\x00\x00/
  enable "openvpn"
}

signature dpd_openvpnhmac_udp_resp {
  ip-proto == udp
  payload /\x40/
  enable "openvpn"
  requires-reverse-signature dpd_openvpnhmac_udp_req
}

signature dpd_openvpn_tcp_req {
  ip-proto == tcp
  payload /..\x38.{8}\x00\x00\x00\x00\x00/
  tcp-state originator
  enable "openvpn"
}

signature dpd_openvpn_tcp_resp {
  ip-proto == tcp
  payload /..\x40/
  tcp-state responder
  enable "openvpn"
  requires-reverse-signature dpd_openvpn_tcp_req
}

signature dpd_openvpnhmac_tcp_req {
  ip-proto == tcp
  payload /..\x38.{36}\x00\x00\x00\x00\x00/
  tcp-state originator
  enable "openvpn"
}

signature dpd_openvpnhmac_tcp_resp {
  ip-proto == tcp
  payload /..\x40/
  tcp-state responder
  enable "openvpn"
  requires-reverse-signature dpd_openvpn_tcp_req
}
