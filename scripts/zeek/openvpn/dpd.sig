signature dpd_openvpn_udp_client {
  ip-proto == udp
  payload /\x38.{8}\x00\x00\x00\x00\x00/
  payload-size == 14
}

signature dpd_openvpn_udp_server {
  ip-proto == udp
  payload /\x40.{9}/
  payload-size == 26
  requires-reverse-signature dpd_openvpn_udp_client
  enable "openvpn"
}

signature dpd_openvpnhmac_udp_client {
  ip-proto == udp
  payload /\x38.{36}\x00\x00\x00\x00\x00/
  payload-size == 42
}

signature dpd_openvpnhmac_udp_server {
  ip-proto == udp
  payload /\x40.{37}/
  payload-size == 54
  requires-reverse-signature dpd_openvpnhmac_udp_client
  enable "openvpnhmac"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  payload /..\x38.{8}\x00\x00\x00\x00\x00/
  payload-size == 16
}

signature dpd_openvpn_tcp_server {
  ip-proto == tcp
  payload /..\x40.{9}/
  payload-size == 28
  requires-reverse-signature dpd_openvpn_tcp_client
  enable "openvpntcp"
}

signature dpd_openvpnhmac_tcp_client {
  ip-proto == tcp
  payload /..\x38.{36}\x00\x00\x00\x00\x00/
  payload-size == 44
}

signature dpd_openvpnhmac_tcp_server {
  ip-proto == tcp
  payload /..\x40.{37}/
  payload-size == 56
  requires-reverse-signature dpd_openvpnhmac_tcp_client
  enable "openvpntcphmac"
}
