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

signature dpd_openvpn_datav1_udp_client {
  ip-proto == udp
  payload /\x30/
  payload-size >= 200
}

signature dpd_openvpn_datav1_udp_server {
  ip-proto == udp
  payload /\x30/
  payload-size >= 200
  requires-reverse-signature dpd_openvpn_datav1_udp_client
  enable "openvpn"
}

signature dpd_openvpn_datav2_udp_client {
  ip-proto == udp
  payload /\x48/
  payload-size >= 200
}

signature dpd_openvpn_datav2_udp_server {
  ip-proto == udp
  payload /\x48/
  payload-size >= 200
  requires-reverse-signature dpd_openvpn_datav2_udp_client
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
  enable "openvpnhmac"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  payload /..\x38.{8}\x00\x00\x00\x00\x00/
}

signature dpd_openvpn_tcp_server {
  ip-proto == tcp
  payload /..\x40.{9}/
  requires-reverse-signature dpd_openvpn_tcp_client
  enable "openvpntcp"
}

signature dpd_openvpn_datav1_tcp_client {
  ip-proto == tcp
  payload /..\x30/
  payload-size >= 200
}

signature dpd_openvpn_datav1_tcp_server {
  ip-proto == tcp
  payload /..\x30/
  payload-size >= 200
  requires-reverse-signature dpd_openvpn_datav1_tcp_client
  enable "openvpntcp"
}

signature dpd_openvpn_datav2_tcp_client {
  ip-proto == tcp
  payload /..\x48/
  payload-size >= 200
}

signature dpd_openvpn_datav2_tcp_server {
  ip-proto == tcp
  payload /..\x48/
  payload-size >= 200
  requires-reverse-signature dpd_openvpn_datav2_tcp_client
  enable "openvpntcp"
}

signature dpd_openvpnhmac_tcp_client {
  ip-proto == tcp
  payload /..\x38.{36}\x00\x00\x00\x00\x00/
}

signature dpd_openvpnhmac_tcp_server {
  ip-proto == tcp
  payload /..\x40.{37}/
  requires-reverse-signature dpd_openvpnhmac_tcp_client
  enable "openvpntcphmac"
}
