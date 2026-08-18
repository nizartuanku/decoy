package decoy

import (
	"encoding/binary"
	"net"
	"strings"
)

// DNSResponder is a tiny authoritative UDP DNS server for DNS-token traps
// (Path A). Delegate a zone to it and any query for a known token hostname is
// recorded as a trip. It answers A queries with a sinkhole address so the
// resolver gets a valid reply and the interaction completes normally.
//
// This is a deliberately minimal responder: enough to catch a resolution, not
// a general-purpose name server. Only start it when a zone has been delegated.
type DNSResponder struct {
	Store       Store
	Sink        *TripSink
	SinkholeIP  net.IP // A-record answer; defaults to 127.0.0.1
	conn        *net.UDPConn
}

// Start binds the responder on addr (e.g. ":53" or "127.0.0.1:0" in tests) and
// serves in a background goroutine until Stop.
func (d *DNSResponder) Start(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	d.conn = conn
	if d.SinkholeIP == nil {
		d.SinkholeIP = net.IPv4(127, 0, 0, 1)
	}
	go d.serve()
	return nil
}

// Addr returns the bound address (useful when tests bind port 0).
func (d *DNSResponder) Addr() net.Addr {
	if d.conn == nil {
		return nil
	}
	return d.conn.LocalAddr()
}

// Stop closes the responder.
func (d *DNSResponder) Stop() {
	if d.conn != nil {
		_ = d.conn.Close()
	}
}

func (d *DNSResponder) serve() {
	buf := make([]byte, 512)
	for {
		n, from, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return // closed
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		d.handle(req, from)
	}
}

func (d *DNSResponder) handle(req []byte, from *net.UDPAddr) {
	name, qtype, ok := parseQuestion(req)
	if !ok {
		return
	}
	if dep, hit := d.matchToken(name); hit {
		_ = d.Sink.Record(Trip{
			DeploymentID: dep.ID,
			Kind:         KindDNSToken,
			Label:        dep.Label,
			SourceIP:     from.IP.String(),
			Detail: map[string]any{
				"qname": name,
				"qtype": qtype,
			},
		})
	}
	resp := buildDNSResponse(req, qtype, d.SinkholeIP)
	if resp != nil {
		_, _ = d.conn.WriteToUDP(resp, from)
	}
}

func (d *DNSResponder) matchToken(qname string) (Deployment, bool) {
	qn := strings.ToLower(strings.TrimSuffix(qname, "."))
	deps, err := d.Store.ListDeployments()
	if err != nil {
		return Deployment{}, false
	}
	for _, dep := range deps {
		if dep.Kind != KindDNSToken {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(dep.Host, "."))
		if qn == host || strings.HasSuffix(qn, "."+host) {
			return dep, true
		}
	}
	return Deployment{}, false
}

// parseQuestion extracts the first question's name (dotted, no trailing dot)
// and qtype from a DNS message. Returns ok=false on malformed input.
func parseQuestion(msg []byte) (name string, qtype uint16, ok bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	if qd < 1 {
		return "", 0, false
	}
	pos := 12
	var labels []string
	for {
		if pos >= len(msg) {
			return "", 0, false
		}
		l := int(msg[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer in a question: unexpected
			return "", 0, false
		}
		if pos+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(msg) {
		return "", 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[pos : pos+2])
	return strings.Join(labels, "."), qtype, true
}

// buildDNSResponse echoes the query as an answer. For A/ANY queries it appends
// one A record pointing at ip; for other types it returns a NOERROR/no-answer
// reply. The question section is copied verbatim and the answer name uses a
// compression pointer to it.
func buildDNSResponse(req []byte, qtype uint16, ip net.IP) []byte {
	if len(req) < 12 {
		return nil
	}
	// End of the question section = after the qname + 4 bytes (qtype+qclass).
	pos := 12
	for pos < len(req) {
		l := int(req[pos])
		pos++
		if l == 0 {
			break
		}
		pos += l
	}
	pos += 4 // qtype + qclass
	if pos > len(req) {
		return nil
	}
	question := req[12:pos]

	out := make([]byte, 0, pos+16)
	// Header: copy id, set flags QR=1 AA=1, QDCOUNT=1.
	header := make([]byte, 12)
	copy(header, req[:12])
	header[2] = 0x84 // QR=1, Opcode=0, AA=1
	header[3] = 0x00 // RA=0, RCODE=0
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT

	answers := uint16(0)
	var ans []byte
	if (qtype == 1 || qtype == 255) && ip.To4() != nil { // A or ANY
		ans = append(ans, 0xC0, 0x0C) // name pointer to offset 12
		ans = append(ans, 0x00, 0x01) // TYPE A
		ans = append(ans, 0x00, 0x01) // CLASS IN
		ans = append(ans, 0x00, 0x00, 0x00, 0x1e) // TTL 30
		ans = append(ans, 0x00, 0x04) // RDLENGTH 4
		ans = append(ans, ip.To4()...)
		answers = 1
	}
	binary.BigEndian.PutUint16(header[6:8], answers) // ANCOUNT

	out = append(out, header...)
	out = append(out, question...)
	out = append(out, ans...)
	return out
}
