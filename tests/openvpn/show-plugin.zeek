# @TEST-EXEC: zeek -NN zeek::openvpn |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
