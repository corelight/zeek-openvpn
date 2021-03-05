
zeek::openvpn
=================================

A plugin to detect and parse OpenVPN in the following modes:

- UDP w/ TLS
- UDP w/ TLS & TLS Auth
- TCP w/ TLS
- TCP w/ TLS & TLS Auth

So far this will not detect shared key mode for UDP or TCP.

If this protocol analyzer is able to parse the TLS information
you will find data in your ssl.log.  TCP TLS support works,
and UDP TLS support will be coming in Zeek >= v4.1.

If you have zkg and you have already run...

```
zkg autoconfig
```

... then you can install this package as so:

```
sudo zkg install zeek-openvpn
```

Now in any Zeek script, just load the plugin and it "just works":

```
@load zeek/openvpn
```

New events for this plugin are found in [events.bif](src/events.bif).
The arguments to the events can be found in [types.zeek](scripts/types.zeek).

#### Examples:

The PCAPs can be found in the [Traces](tests/Traces) directory.

```
$ cat test.zeek
@load zeek/openvpn
@load ja3

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg) { print cat(msg); }
event OpenVPN::ack_message(c: connection, is_orig: bool, msg: OpenVPN::AckMsg) { print cat(msg); }
event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::DataMsg) { print cat(msg); }

$ zeek -Cr 9841-openvpn_udp_tlsauth.pcap test.zeek
[opcode=7, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=0, data_len=0, msg_type=7]
[opcode=8, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[0], remote_session_id=\x07I\x81\xbdyzU\x8d, packet_id=0, data_len=0, msg_type=8]
[opcode=5, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[0], remote_session_id=f\xf9G\x09\x18\x8d\xae+, msg_type=5]
[opcode=4, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=1, data_len=100, msg_type=4]
[opcode=4, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=2, data_len=100, msg_type=4]
[opcode=4, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=3, data_len=26, msg_type=4]
[opcode=5, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[1], remote_session_id=\x07I\x81\xbdyzU\x8d, msg_type=5]
[opcode=5, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[2], remote_session_id=\x07I\x81\xbdyzU\x8d, msg_type=5]
[opcode=4, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[3], remote_session_id=\x07I\x81\xbdyzU\x8d, packet_id=1, data_len=100, msg_type=4]
...
[opcode=5, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[38], remote_session_id=\x07I\x81\xbdyzU\x8d, msg_type=5]
[opcode=4, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=53, data_len=100, msg_type=4]
[opcode=4, key_id=0, session_id=f\xf9G\x09\x18\x8d\xae+, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=54, data_len=54, msg_type=4]
[opcode=5, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[53], remote_session_id=f\xf9G\x09\x18\x8d\xae+, msg_type=5]
[opcode=5, key_id=0, session_id=\x07I\x81\xbdyzU\x8d, packet_id_ack_array=[54], remote_session_id=f\xf9G\x09\x18\x8d\xae+, msg_type=5]
[opcode=6, key_id=0, data_len=52, peer_id=<uninitialized>, msg_type=6]
[opcode=6, key_id=0, data_len=52, peer_id=<uninitialized>, msg_type=6]

$ grep openvpn conn.log
1353592367.157643	C69gk04obOrLdomzv9	192.168.56.103	60514	192.168.56.102	1194	udp	openvpnhmac	12.839080	7932	9373	SF	-	-	0	Dd	93	10536	91	11921	-
```

If the TLS handshake can be captured, you will find additional information in ssl.log:


```
$ zeek -Cr 9840-openvpn_tcp_nontlsauth.pcap test.zeek
[opcode=7, key_id=0, session_id=Pz(\xa7\x82ux\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=0, data_len=0, msg_type=7]
[opcode=8, key_id=0, session_id=\x9a\xd7G\xbe\xb2M\x8a\x1b, packet_id_ack_array=[0], remote_session_id=Pz(\xa7\x82ux\x8d, packet_id=0, data_len=0, msg_type=8]
[opcode=5, key_id=0, session_id=Pz(\xa7\x82ux\x8d, packet_id_ack_array=[0], remote_session_id=\x9a\xd7G\xbe\xb2M\x8a\x1b, msg_type=5]
[opcode=4, key_id=0, session_id=Pz(\xa7\x82ux\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=1, data_len=100, msg_type=4]
[opcode=4, key_id=0, session_id=Pz(\xa7\x82ux\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=2, data_len=100, msg_type=4]
[opcode=4, key_id=0, session_id=Pz(\xa7\x82ux\x8d, packet_id_ack_array=[], remote_session_id=<uninitialized>, packet_id=3, data_len=26, msg_type=4]
[opcode=5, key_id=0, session_id=\x9a\xd7G\xbe\xb2M\x8a\x1b, packet_id_ack_array=[1], remote_session_id=Pz(\xa7\x82ux\x8d, msg_type=5]
[opcode=5, key_id=0, session_id=\x9a\xd7G\xbe\xb2M\x8a\x1b, packet_id_ack_array=[2], remote_session_id=Pz(\xa7\x82ux\x8d, msg_type=5]
...
[opcode=6, key_id=0, data_len=124, peer_id=<uninitialized>, msg_type=6]
[opcode=6, key_id=0, data_len=124, peer_id=<uninitialized>, msg_type=6]
[opcode=6, key_id=0, data_len=124, peer_id=<uninitialized>, msg_type=6]
[opcode=6, key_id=0, data_len=124, peer_id=<uninitialized>, msg_type=6]
[opcode=6, key_id=0, data_len=52, peer_id=<uninitialized>, msg_type=6]

$ cat conn.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-03-05-15-08-12
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1358197736.781122	CW4BxU1d0sa8b429pg	192.168.56.103	39772	192.168.56.102	1194	tcp	ssl,openvpntcp	32.021256	6986	7709	S1	-	-	0	ShADad	100	12194	95	12657	-
#close	2021-03-05-15-08-12

$ cat ssl.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#open	2021-03-05-15-08-12
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	cert_chain_fuids	client_cert_chain_fuids	subject	issuer	client_subject	client_issuer	ja3	ja3s
#types	time	string	addr	port	addr	port	string	string	string	string	bool	string	string	bool	vector[string]	vector[string]	string	string	string	string	string	string
1358197737.844659	CW4BxU1d0sa8b429pg	192.168.56.103	39772	192.168.56.102	1194	TLSv10	TLS_DHE_RSA_WITH_AES_256_CBC_SHA	-	-	F	-	-	T	FIgTSu4XxFLZ2E4pV8,FBAmci2bnwWasltS9i	FdSmvb4Z4RmNS42M3g,FHh4nUMj6vdVO6Jtf	emailAddress=PRO3,name=PRO3,CN=PRO3,OU=PRO3,O=PRO3,L=PRO3,ST=OE,C=AT	emailAddress=PRO3,name=PRO3,CN=PRO3,OU=PRO3,O=PRO3,L=PRO3,ST=OE,C=AT	emailAddress=PRO3,name=PRO3,CN=PRO3-Client,OU=PRO3,O=PRO3,L=PRO3,ST=OE,C=AT	emailAddress=PRO3,name=PRO3,CN=PRO3,OU=PRO3,O=PRO3,L=PRO3,ST=OE,C=AT	f0d20361ae57a5c81d94ac774a736a52	7a2f70a16da750662fc0291d88ebddf8
#close	2021-03-05-15-08-12
```



#### Additional Documentation:

- https://build.openvpn.net/doxygen/network_protocol.html
- https://openvpn.net/community-resources/openvpn-protocol/
- https://wiki.wireshark.org/OpenVPN

### License:

Copyright (c) 2021, Corelight, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

(1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

(2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

(3) Neither the name of Corelight nor the names of any contributors
    may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.