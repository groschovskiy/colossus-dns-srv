package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
)

type DNSRecord struct {
	Name     string
	Type     uint16
	Content  string
	TTL      uint32
	Priority uint16
}

var (
	records    map[string][]DNSRecord
	recordLock sync.RWMutex
)

func main() {
	records = make(map[string][]DNSRecord)

	mysql.RegisterTLSConfig("tidb", &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "gateway01.eu-central-1.prod.aws.tidbcloud.com",
	})

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?tls=tidb",
		os.Getenv("TIDB_USER"),
		os.Getenv("TIDB_PASSWORD"),
		os.Getenv("TIDB_HOST"),
		os.Getenv("TIDB_PORT"),
		os.Getenv("TIDB_DATABASE")))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := loadRecords(db); err != nil {
		log.Fatalf("Failed to load records: %v", err)
	}

	server := &dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)

	log.Println("Starting DNS server on :53")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func loadRecords(db *sql.DB) error {
	rows, err := db.Query("SELECT name, type, content, ttl, priority FROM dns_records")
	if err != nil {
		return err
	}
	defer rows.Close()

	recordLock.Lock()
	defer recordLock.Unlock()

	for rows.Next() {
		var r DNSRecord
		var recordType string
		err := rows.Scan(&r.Name, &recordType, &r.Content, &r.TTL, &r.Priority)
		if err != nil {
			return err
		}
		r.Type = dns.StringToType[recordType]
		r.Name = dns.Fqdn(r.Name)
		records[r.Name] = append(records[r.Name], r)
	}

	return rows.Err()
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Printf("Received DNS request from %s", clientIP)

	for _, question := range r.Question {
		name := question.Name
		qtype := question.Qtype
		log.Printf("Query for %s (type %s)", name, dns.TypeToString[qtype])

		recordLock.RLock()
		if recs, ok := records[name]; ok {
			for _, rec := range recs {
				if rec.Type == qtype || qtype == dns.TypeANY {
					rr := createRR(rec)
					if rr != nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
		recordLock.RUnlock()

		if len(m.Answer) == 0 {
			labels := dns.SplitDomainName(name)
			for i := 0; i < len(labels); i++ {
				wildcard := "*." + strings.Join(labels[i:], ".") + "."
				if recs, ok := records[wildcard]; ok {
					for _, rec := range recs {
						if rec.Type == qtype || qtype == dns.TypeANY {
							rr := createRR(rec)
							if rr != nil {
								rr.Header().Name = name
								m.Answer = append(m.Answer, rr)
							}
						}
					}
					break
				}
			}
		}
	}

	w.WriteMsg(m)
}

func createRR(rec DNSRecord) dns.RR {
	switch rec.Type {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL},
			A:   net.ParseIP(rec.Content),
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rec.TTL},
			AAAA: net.ParseIP(rec.Content),
		}
	case dns.TypeMX:
		parts := strings.Fields(rec.Content)
		if len(parts) != 2 {
			log.Printf("Invalid MX record format: %s", rec.Content)
			return nil
		}
		return &dns.MX{
			Hdr:        dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec.TTL},
			Preference: rec.Priority,
			Mx:         parts[1],
		}
	case dns.TypeSRV:
		parts := strings.Fields(rec.Content)
		if len(parts) != 3 {
			log.Printf("Invalid SRV record format: %s", rec.Content)
			return nil
		}
		weight, _ := fmt.Sscanf(parts[0], "%d", new(uint16))
		port, _ := fmt.Sscanf(parts[1], "%d", new(uint16))
		return &dns.SRV{
			Hdr:      dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: rec.TTL},
			Priority: rec.Priority,
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   parts[2],
		}
	case dns.TypeTXT:
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
			Txt: []string{rec.Content},
		}
	default:
		log.Printf("Unsupported record type: %d", rec.Type)
		return nil
	}
}
