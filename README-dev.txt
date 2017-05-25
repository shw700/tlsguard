The following rules will intercept all traffic destined to port 6697 and force use of a valid certificate.

iptables -I OUTPUT 1 --proto tcp -m connmark --mark 666 -j REJECT --reject-with tcp-reset
iptables -I OUTPUT 2 -m conntrack --ctstate NEW --proto tcp --dport 6697 -j CONNMARK --set-mark 7
iptables -I OUTPUT 3 -m conntrack --ctstate NEW --proto tcp --dport 6697 -j NFQUEUE --queue-num 1 --queue-bypass
iptables -I OUTPUT 4 --proto tcp -m connmark --mark 7 -j NFQUEUE --queue-num 1 --queue-bypass

iptables -I INPUT 1 --proto tcp -m connmark --mark 666 -j REJECT --reject-with tcp-reset
iptables -I INPUT 2 --proto tcp -m connmark --mark 7 -j NFQUEUE --queue-num 1 --queue-bypass





Please also note the value OVERRIDE_ROOTPATH set in filter.go.
There is currently a situation where calling Verify() on an X509 certificate can hang forever,
which seems to be an issue with ASN1 parsing of the root certificate store (golang bug)?
You can correct this bug by supplying your own "good" root.
It would really be nice to find out what's going on and remove this completely, though.
