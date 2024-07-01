package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/miekg/dns"
	_ "github.com/go-sql-driver/mysql"
)

type DNSRecord struct {
	Name     string
	Type     uint16
	Content  string
	TTL      uint32
	Priority uint16 // For MX and SRV records
}

var (
	records    map[string][]DNSRecord
	recordLock sync.RWMutex
)

func main() {
	records = make(map[string][]DNSRecord)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
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
		log.Printf("Query for %s", question.Name)
		recordLock.RLock()
		if recs, ok := records[question.Name]; ok {
			for _, rec := range recs {
				if rec.Type == question.Qtype {
					rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rec.Name, rec.TTL, dns.TypeToString[rec.Type], rec.Content))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
		recordLock.RUnlock()
	}

	w.WriteMsg(m)
}