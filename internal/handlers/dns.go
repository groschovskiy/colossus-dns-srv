package handlers

import (
	"log"
	"net"
	"strings"

	"colossus-dns/internal/ctl"

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
		handleRecords(m, recs, name, qtype, records, 0)
	}

	if len(m.Answer) == 0 {
		handleWildcardQuery(m, name, qtype, records)
	}
}

func handleRecords(m *dns.Msg, recs []ctl.DNSRecord, name string, qtype uint16, allRecords map[string][]ctl.DNSRecord, depth int) {
	if depth > 10 {
		log.Printf("CNAME resolution depth exceeded for %s", name)
		return
	}

	for _, rec := range recs {
		if rec.Type == dns.TypeCNAME {
			rr := ctl.CreateRR(rec)
			m.Answer = append(m.Answer, rr)

			if qtype != dns.TypeCNAME {
				cname := rec.Content
				if cnameRecs, ok := allRecords[cname]; ok {
					handleRecords(m, cnameRecs, cname, qtype, allRecords, depth+1)
				}
			}
		} else if rec.Type == qtype || qtype == dns.TypeANY {
			rr := ctl.CreateRR(rec)
			if rr != nil {
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
			handleRecords(m, recs, name, qtype, records, 0)
			break
		}
	}
}
