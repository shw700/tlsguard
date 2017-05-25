package main

import (
	"fmt"
	"sync"
	"net"
	"errors"
	"encoding/binary"
	"crypto/x509"
//	"crypto/md5"
	"io/ioutil"

	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
	nfconntrack "github.com/subgraph/go-nfnetlink/conntrack"
	"github.com/google/gopacket/layers"
)


// TODO: Uncomment the lines with removeTCPStream() and get rid of STATE_DENIED, because
// conntrack should be handling this for us.
// Also walk the connection tables periodically to remove stale connections.


var OVERRIDE_ROOTPATH = "/etc/ssl/certs/ca-certificates.working"
// var OVERRIDE_ROOTPATH = ""
// to use system default


const (
        STATE_RECORD_HEADER = iota
	STATE_RECORD_DATA
	STATE_WAITING_CERT
	STATE_DENIED
)

var stateStrings = map[int]string {
	STATE_RECORD_HEADER: "RECORD_HEADER",
	STATE_RECORD_DATA: "RECORD_DATA",
	STATE_WAITING_CERT: "WAITING_CERT",
	STATE_DENIED: "DENIED",
}

const RECORD_HEADER_SIZE = 5


type TCPStream struct {
	srcip       net.IP
	srcport     uint16
	dstip       net.IP
	dstport     uint16
	sentb       []byte
	recvb       []byte
	established bool
	state       int
	waitn       uint
	dispatched  bool
}

var TCPStreams []*TCPStream
var streamLock = &sync.Mutex{}


func dumpTCPStreams() {
	streamLock.Lock()
	defer streamLock.Unlock()

	fmt.Println("-- Total # tracked streams: ", len(TCPStreams))
	for i, stream := range TCPStreams {
		fmt.Printf("-- %d: %v:%v -> %v:%v (sent = %db, recv = %db)\n", i+1,
			stream.srcip, stream.srcport, stream.dstip, stream.dstport, len(stream.sentb), len(stream.recvb))
/*		fmt.Printf("%d: %v:%v -> %v:%v\n", i+1, stream.srcip, stream.srcport, stream.dstip, stream.dstport)
		fmt.Printf("   sent %db -> %v\n", len(stream.sentb), "xxx")
		fmt.Printf("   recv %db -> %v\n", len(stream.recvb), "xxx") */

//		fmt.Printf("   sent %db -> %v\n", len(stream.sentb), string(stream.sentb))
//		fmt.Printf("   recv %db -> %v\n", len(stream.recvb), string(stream.recvb))
	}
}

func addTCPStream(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16) *TCPStream {
	streamLock.Lock()
	defer streamLock.Unlock()

	var ostream *TCPStream = nil
	for _, stream := range TCPStreams {
		if stream.srcip.Equal(srcip) && stream.srcport == srcport && stream.dstip.Equal(dstip) && stream.dstport == dstport {
			fmt.Println("Unexpected error: could not add already tracked TCP stream!")
			return nil
		} else if stream.srcip.Equal(dstip) && stream.srcport == dstport && stream.dstip.Equal(srcip) && stream.dstport == srcport {
			ostream = stream
		}
	}

	if ostream != nil {
		if ostream.established {
			fmt.Println("Unexpected error: tracked stream was not in half-established state, as expected!")
			return nil
		}
		ostream.established = true
		return ostream
	}

	stream := &TCPStream{srcip: srcip, srcport: srcport, dstip: dstip, dstport: dstport, state: STATE_RECORD_HEADER, established: false, waitn: RECORD_HEADER_SIZE}
	TCPStreams = append(TCPStreams, stream)
	return stream
}

func removeTCPStream(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16) bool {
	streamLock.Lock()
	defer streamLock.Unlock()

	for i, stream := range TCPStreams {
		if (stream.srcip.Equal(srcip) && stream.srcport == srcport && stream.dstip.Equal(dstip) && stream.dstport == dstport) ||
			(stream.srcip.Equal(dstip) && stream.srcport == dstport && stream.dstip.Equal(srcip) && stream.dstport == srcport) {
			fmt.Println("FOUND IT AND DELETING!")
			TCPStreams = append(TCPStreams[:i], TCPStreams[i+1:]...)
			return true
		}
	}

	return false
}

func queueTCPData(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16, data []byte) *TCPStream {
	streamLock.Lock()
	defer streamLock.Unlock()
	for _, stream := range TCPStreams {
		if stream.srcip.Equal(srcip) && stream.srcport == srcport && stream.dstip.Equal(dstip) && stream.dstport == dstport {
			if !stream.established {
				fmt.Println("Unexpected error; found TCP connection but it wasn't established!")
				return nil
			}
			stream.sentb = append(stream.sentb, data...)
			return stream
		} else if stream.srcip.Equal(dstip) && stream.srcport == dstport && stream.dstip.Equal(srcip) && stream.dstport == srcport {
			if !stream.established {
				fmt.Println("Unexpected error; found TCP connection but it wasn't established!")
				return nil
			}
			stream.recvb = append(stream.recvb, data...)
			return stream
		}
	}

	return nil
}

func filterPacket(pkt *nfqueue.NFQPacket) {
	if dontFilter(pkt) {
		pkt.Accept()
		return
	}

	srcip, dstip := getPacketIPAddrs(pkt)
	tcpLayer := pkt.Packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		pkt.Accept()
		return
	}


	tcp, _ := tcpLayer.(*layers.TCP)
	sport, dport := uint16(tcp.SrcPort), uint16(tcp.DstPort)
//	fmt.Printf("XXX: src = %v, dst = %v\n", sport, dport)

	if tcp.SYN {
		fmt.Printf("Adding TCP stream: %v:%v -> %v:%v\n", srcip, sport, dstip, dport)
		addTCPStream(srcip, sport, dstip, dport)
	}
	if tcp.FIN {
		fmt.Printf("Removing (FIN) TCP stream: %v:%v -> %v:%v\n", srcip, sport, dstip, dport)
		removeTCPStream(srcip, sport, dstip, dport)
	}
	if tcp.RST {
		fmt.Printf("Removing (RST) TCP stream: %v:%v -> %v:%v\n", srcip, sport, dstip, dport)
		removeTCPStream(srcip, sport, dstip, dport)
	}

	data := tcpLayer.LayerPayload()
//	fmt.Println("XXX: data bytes = ", len(data), " / data = ", string(data))

	if len(data) == 0 {
		pkt.Accept()
		return
	}

	stream := queueTCPData(srcip, sport, dstip, dport, data)
	if stream == nil {
		fmt.Printf("Error queueing TCP data to buffer: %v:%v -> %v:%v / nactive = %d\n", srcip, sport, dstip, dport, len(TCPStreams))
		pkt.Accept()
		return
	}

	if stream.state == STATE_DENIED {
		fmt.Println("Dropping data from denied session.")
		pkt.Drop()
		return
	}

	dumpTCPStreams()

	if len(stream.recvb) >= int(stream.waitn) {
		streamLock.Lock()
		if !stream.dispatched {
			streamLock.Unlock()
			dispatchTLSGuard(pkt, stream)
		} else {
			streamLock.Unlock()
		}

		return
	}

	pkt.Accept()
}

func dontFilter(pkt *nfqueue.NFQPacket) bool {
	_, dstip := getPacketIPAddrs(pkt)
	if pkt.Packet.Layer(layers.LayerTypeTCP) == nil {
		return true
	}
	return dstip.IsLoopback() || dstip.IsLinkLocalMulticast()
}

func getPacketIPAddrs(pkt *nfqueue.NFQPacket) (net.IP, net.IP) {
	ipv4 := true
	ipLayer := pkt.Packet.Layer(layers.LayerTypeIPv4)

	if ipLayer == nil {
		ipv4 = false
		ipLayer = pkt.Packet.Layer(layers.LayerTypeIPv6)
	}

	if ipLayer == nil {
		if ipv4 {
			return net.IP{0,0,0,0}, net.IP{0,0,0,0}
		}
		return net.IP{}, net.IP{}
	}

	if !ipv4 {
		ip6, _ := ipLayer.(*layers.IPv6)
		return ip6.SrcIP, ip6.DstIP
	}

	ip4, _ := ipLayer.(*layers.IPv4)
	return ip4.SrcIP, ip4.DstIP
}

func dispatchTLSGuard(pkt *nfqueue.NFQPacket, stream *TCPStream) {
	fmt.Printf("TLS guard dispatched with %d bytes of needed %d, and state = %s\n", len(stream.recvb), stream.waitn, stateStrings[stream.state])

	if !stream.established || len(stream.recvb) < int(stream.waitn) {
		pkt.Accept()
		return
	}

	if stream.state == STATE_RECORD_HEADER {
		rtype := stream.recvb[0]
		if rtype != 0x16 {
//			removeTCPStream(srcip, sport, dstip, dport)
			stream.state = STATE_DENIED
			fmt.Println("Dropping packet: data did not appear to be part of TLS negotiation!")
			markPacketBad(stream.srcip, stream.srcport, stream.dstip, stream.dstport)
			pkt.Drop()
			return
		}

//		vers := binary.BigEndian.Uint16(stream.recvb[1:3])
		flen := binary.BigEndian.Uint16(stream.recvb[3:5])

//		fmt.Printf("XXX: rtype = %x, vers = %x, flen = %d\n", rtype, vers, flen)
		stream.waitn = uint(flen)
		stream.recvb = stream.recvb[RECORD_HEADER_SIZE:]
		stream.state = STATE_RECORD_DATA
	} else if stream.state == STATE_RECORD_DATA {
//		fmt.Println("Reading opaque data of length: ", stream.waitn, " | first byte = %x", stream.recvb[0])
//		fmt.Printf("XXX: Reading opaque data of length: %d | first byte = %x\n", stream.waitn, stream.recvb[0])

		if stream.recvb[0] == 0xb {
			fmt.Println("-------- checking certificate")
			go doCheckCert(pkt, stream, "")
			return
		}

		stream.recvb = stream.recvb[stream.waitn:]
		stream.waitn = RECORD_HEADER_SIZE
		stream.state = STATE_RECORD_HEADER
	} else if stream.state == STATE_WAITING_CERT {
		fmt.Println("GOT CERTIFICATE!")
	}

//	fmt.Println("XXX: WE GOT BYTES: ", len(stream.recvb))

	pkt.Accept()
	return
}

func doCheckCert(pkt *nfqueue.NFQPacket, stream *TCPStream, fqdn string) {
	streamLock.Lock()

	if stream.dispatched {
		streamLock.Unlock()
		return
	}

	stream.dispatched = true
	streamLock.Unlock()
	err := checkCert(stream, fqdn)

	if err != nil {
		//removeTCPStream(srcip, sport, dstip, dport)
		stream.state = STATE_DENIED
		fmt.Println("Dropping packet because of certificate validation failure: ", err)

		err := markPacketBad(stream.srcip, stream.srcport, stream.dstip, stream.dstport)
		if err != nil {
			fmt.Println("Error occurred marking packet OK: ", err)
		}
		pkt.Drop()
		return
	}

	// Verification succeedd!
	fmt.Println("Certificate verification succeeded!")
	removeTCPStream(stream.srcip, stream.srcport, stream.dstip, stream.dstport)

	err = markPacketOK(stream.srcip, stream.srcport, stream.dstip, stream.dstport)
	if err != nil {
		fmt.Println("Error occurred marking packet OK: ", err)
	}

	pkt.Accept()
	return
}

func checkCert(stream *TCPStream, fqdn string) error {
//fmt.Println("XXX: check len = ", len(data))
	serverHelloBody := stream.recvb[4:]
//fmt.Println("XXX: body len = ", len(serverHelloBody))
	certChainLen := int(int(serverHelloBody[0])<<16 | int(serverHelloBody[1])<<8 | int(serverHelloBody[2]))
//fmt.Println("XXX: cert chain len = ", certChainLen)
	remaining := certChainLen
	pos := serverHelloBody[3:certChainLen]

	// var certChain []*x509.Certificate
	var verifyOptions x509.VerifyOptions

	if fqdn != "" {
		verifyOptions.DNSName = fqdn
	}

	pool := x509.NewCertPool()
	var c *x509.Certificate

	for remaining > 0 {
//fmt.Println("XXX: Remaining: ", remaining)
		certLen := int(int(pos[0])<<16 | int(pos[1])<<8 | int(pos[2]))
//fmt.Println("XXX: next certlen = ", certLen)
//				fmt.Printf("Certs chain len %d, cert 1 len %d:\n", certChainLen, certLen)
		cert := pos[3 : 3+certLen]
//fmt.Printf("XXX: cert = %x\n", md5.Sum(cert))
		certs, err := x509.ParseCertificates(cert)
//fmt.Println("certs = ", certs[0])
		if remaining == certChainLen {
			c = certs[0]
		} else {
			pool.AddCert(certs[0])
		}
		// certChain = append(certChain, certs[0])
		if err != nil {
			return err
		}
		remaining = remaining - certLen - 3
		if remaining > 0 {
			pos = pos[3+certLen:]
		}
	}
	verifyOptions.Intermediates = pool

	if OVERRIDE_ROOTPATH != "" {
		roots := x509.NewCertPool()

		pemdata, err := ioutil.ReadFile(OVERRIDE_ROOTPATH)

		if err != nil {
			fmt.Println("Error: could not read root certificate store: ", err)
		} else {
			fmt.Println("Loading root store...")
			if !roots.AppendCertsFromPEM(pemdata) {
				fmt.Println("Error: could not append certificates from root store at: ", OVERRIDE_ROOTPATH)
			} else {
				verifyOptions.Roots = roots
				fmt.Println("Successfully loaded alternate root store from: ", OVERRIDE_ROOTPATH)
			}
		}
	}


//fmt.Println("Total of subject names = ", len(c.Subject.Names))
//fmt.Println("SUBJECT EXTRA NAMES = ", c.Subject.ExtraNames)
	subjname := ""

	if c.Subject.Names[0].Type.String() == "2.5.4.3" {
		fmt.Println(c.Subject.Names[0].Value)
		subjname = c.Subject.Names[0].Value.(string)
	}

	if !addrMatchesHosts(stream.dstip, subjname, c.DNSNames) {
		return errors.New("None of certificate hostnames matched IP address of connection")
	}


	fmt.Println("Verifying certificate...")
	_, err := c.Verify(verifyOptions)
//return errors.New("Certificate failed validation check")
//fmt.Println("Verification complete")
	if err != nil {
		return err
	} else {
		return nil
	}

	return errors.New("Certificate failed validation check")
}

func sliceHasStr(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func addrMatchesHosts(addr net.IP, hostname string, altnames []string) bool {
	fmt.Printf("Running DNS match of %s against %s and %d alternative names ...\n", addr, hostname, len(altnames))

	if hostname != "" {
		addrs, err := net.LookupHost(hostname)

		if err != nil {
			fmt.Printf("Error looking up hostname %s: %v\n", hostname, err)
		} else {
			fmt.Println("Addrs: ", addrs)

			if sliceHasStr(addrs, addr.String()) {
				return true
			}
		}
	}

	for _, altname := range altnames {
		addrs, err := net.LookupHost(altname)

		if err != nil {
			fmt.Printf("Error looking up alt hostname%s: %v\n", altname, err)
		} else {
			fmt.Println("Alt hostname addresses: ", altname, ": ", addrs)

			if sliceHasStr(addrs, addr.String()) {
				return true
			}
		}
	}

	return false
}

var MARK_GOOD = 31337
var MARK_BAD = 666

func markPacketOK(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16) error {
	fmt.Println("Marking packet OK!")
	nq := nfconntrack.NewNFConntrack()
        err := nq.MarkConnection(srcip, srcport, dstip, dstport, uint32(MARK_GOOD))
	nq.Close()
	return err
}

func markPacketBad(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16) error {
	fmt.Println("Marking packet bad!")
	nq := nfconntrack.NewNFConntrack()
        err := nq.MarkConnection(srcip, srcport, dstip, dstport, uint32(MARK_BAD))
	nq.Close()
	return err
}
