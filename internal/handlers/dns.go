package handlers

import (
	"log"
	"net"
	"runtime/debug"
	"strings"

	"colossus-dns/internal/ctl"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

type Geolocation struct {
	Status      string `json:"status"`
	Continent   string `json:"continent"`
	CountryCode string `json:"country_code"`
}

var db *geoip2.Reader

func init() {
	var err error
	db, err = geoip2.Open("./data/GeoLite2.mmdb")
	if err != nil {
		log.Fatal(err)
	}
}

func getContinent(ipAddress string) (string, error) {
	record, err := db.City(net.ParseIP(ipAddress))
	if err != nil {
		return "", err
	}
	return record.Continent.Names["en"], nil
}

func HandleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Recovered from panic in HandleDNSRequest: %v\nStack trace:\n%s", rec, debug.Stack())
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
		}
	}()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Printf("Received DNS request from %s", clientIP)
	continent, err := getContinent(clientIP)
	if err != nil {
		log.Printf("Failed to get continent for %s: %v", clientIP, err)
		continent = "" // Empty if continent couldn't be determined
	} else {
		log.Printf("Continent for %s: %s", clientIP, continent)
	}

	for _, question := range r.Question {
		name := question.Name
		qtype := question.Qtype
		log.Printf("Query for %s (type %s)", name, dns.TypeToString[qtype])

		handleQuestion(m, name, qtype, continent)
	}

	w.WriteMsg(m)
}

func handleQuestion(m *dns.Msg, name string, qtype uint16, continent string) {
	records := ctl.GetRecords()

	if recs, ok := records[name]; ok {
		handleRecords(m, recs, name, qtype, records, 0, continent)
	}

	if len(m.Answer) == 0 {
		handleWildcardQuery(m, name, qtype, records, continent)
	}
}

func handleRecords(m *dns.Msg, recs []ctl.DNSRecord, name string, qtype uint16, allRecords map[string][]ctl.DNSRecord, depth int, continent string) {
	if depth > 10 {
		log.Printf("CNAME resolution depth exceeded for %s", name)
		return
	}

	var matchingRecords []ctl.DNSRecord
	var nonGeoRecords []ctl.DNSRecord

	for _, rec := range recs {
		if rec.GeoContinent == continent {
			matchingRecords = append(matchingRecords, rec)
		} else if rec.GeoContinent == "" {
			nonGeoRecords = append(nonGeoRecords, rec)
		}
	}

	// If no continent-specific records found, use all non-geo records
	if len(matchingRecords) == 0 {
		matchingRecords = nonGeoRecords
	}

	for _, rec := range matchingRecords {
		if rec.Type == dns.TypeCNAME || rec.Type == qtype || qtype == dns.TypeANY {
			rr := ctl.CreateRR(rec)
			if rr != nil {
				m.Answer = append(m.Answer, rr)

				if rec.Type == dns.TypeCNAME && qtype != dns.TypeCNAME {
					cname := rec.Content
					if cnameRecs, ok := allRecords[cname]; ok {
						handleRecords(m, cnameRecs, cname, qtype, allRecords, depth+1, continent)
					}
				}
			}
		}
	}
}

func handleWildcardQuery(m *dns.Msg, name string, qtype uint16, records map[string][]ctl.DNSRecord, continent string) {
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels); i++ {
		wildcard := "*." + strings.Join(labels[i:], ".") + "."
		if recs, ok := records[wildcard]; ok {
			handleRecords(m, recs, name, qtype, records, 0, continent)
			break
		}
	}
}
