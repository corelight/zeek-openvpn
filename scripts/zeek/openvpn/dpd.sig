signature dpd_openvpn_udp_client {
  ip-proto == udp
  payload /\x38.{8}\x00\x00\x00\x00\x00/
  requires-reverse-signature dpd_openvpn_udp_server
  enable "openvpn"
}

signature dpd_openvpn_udp_server {
  ip-proto == udp
  payload /\x40/
  enable "openvpn"
}

signature dpd_openvpn_datav1_udp_client {
  ip-proto == udp
  payload /\x30/
  requires-reverse-signature dpd_openvpn_datav1_udp_server
  enable "openvpn"
}

signature dpd_openvpn_datav1_udp_server {
  ip-proto == udp
  payload /\x30/
  enable "openvpn"
}

signature dpd_openvpnhmac_udp_client {
  ip-proto == udp
  payload /\x38.{36}\x00\x00\x00\x00\x00/
  requires-reverse-signature dpd_openvpnhmac_udp_server
  enable "openvpn"
}

signature dpd_openvpnhmac_udp_server {
  ip-proto == udp
  payload /\x40/
  enable "openvpn"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  payload /..\x38.{8}\x00\x00\x00\x00\x00/
  tcp-state originator
  requires-reverse-signature dpd_openvpn_tcp_server
  enable "openvpn"
}

signature dpd_openvpn_tcp_server {
  ip-proto == tcp
  payload /..\x40/
  tcp-state responder
  enable "openvpn"
}

signature dpd_openvpnhmac_tcp_client {
  ip-proto == tcp
  payload /..\x38.{36}\x00\x00\x00\x00\x00/
  tcp-state originator
  requires-reverse-signature dpd_openvpn_tcp_server
  enable "openvpn"
}

signature dpd_openvpnhmac_tcp_server {
  ip-proto == tcp
  payload /..\x40/
  tcp-state responder
  enable "openvpn"
}
