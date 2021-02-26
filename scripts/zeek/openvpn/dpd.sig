signature dpd_openvpn_udp_client {
  ip-proto == udp
  payload /\x38.{8}\x00\x00\x00\x00\x00/
}

signature dpd_openvpn_udp_server {
  ip-proto == udp
  payload /\x40.{9}/
  requires-reverse-signature dpd_openvpn_udp_client
  enable "openvpn"
}

signature dpd_openvpnhmac_udp_client {
  ip-proto == udp
  payload /\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmac_udp_server {
  ip-proto == udp
  payload /\x40.{37}/
  requires-reverse-signature dpd_openvpnhmac_udp_client
  enable "openvpn"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  enable "openvpn"
}

signature dpd_openvpn_tcp_server {
  ip-proto == tcp
  payload /..\x40.{9}/
  requires-reverse-signature dpd_openvpn_tcp_client
  enable "openvpn"
}

signature dpd_openvpnhmac_tcp_client {
  ip-proto == tcp
  payload /..\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmac_tcp_server {
  ip-proto == tcp
  payload /..\x40.{37}/
  requires-reverse-signature dpd_openvpnhmac_tcp_client
  enable "openvpn"
}
