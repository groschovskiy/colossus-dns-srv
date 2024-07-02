package handlers

import (
	"log"
	"net"
	"strings"

	"github.com/groschovskiy/colossus-dns-srv/internal/ctl"

	"github.com/miekg/dns"
)

func HandleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Printf("Received DNS request from %s", clientIP)

	for _, question := range r.Question {
		name := question.Name
		qtype := question.Qtype
		log.Printf("Query for %s (type %s)", name, dns.TypeToString[qtype])

		handleQuestion(m, name, qtype)
	}

	w.WriteMsg(m)
}

func handleQuestion(m *dns.Msg, name string, qtype uint16) {
	records := ctl.GetRecords()

	if recs, ok := records[name]; ok {
		appendMatchingRecords(m, recs, qtype)
	}

	if len(m.Answer) == 0 {
		handleWildcardQuery(m, name, qtype, records)
	}
}

func appendMatchingRecords(m *dns.Msg, recs []ctl.DNSRecord, qtype uint16) {
	for _, rec := range recs {
		if rec.Type == qtype || qtype == dns.TypeANY {
			if rr := ctl.CreateRR(rec); rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func handleWildcardQuery(m *dns.Msg, name string, qtype uint16, records map[string][]ctl.DNSRecord) {
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels); i++ {
		wildcard := "*." + strings.Join(labels[i:], ".") + "."
		if recs, ok := records[wildcard]; ok {
			for _, rec := range recs {
				if rec.Type == qtype || qtype == dns.TypeANY {
					if rr := ctl.CreateRR(rec); rr != nil {
						rr.Header().Name = name
						m.Answer = append(m.Answer, rr)
					}
				}
			}
			break
		}
	}
}
