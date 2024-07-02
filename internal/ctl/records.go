package ctl

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

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

func InitRecords() {
	records = make(map[string][]DNSRecord)
}

func GetRecords() map[string][]DNSRecord {
	recordLock.RLock()
	defer recordLock.RUnlock()
	return records
}

func CreateRR(rec DNSRecord) dns.RR {
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
		return createMXRecord(rec)
	case dns.TypeSRV:
		return createSRVRecord(rec)
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

func createMXRecord(rec DNSRecord) *dns.MX {
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
}

func createSRVRecord(rec DNSRecord) *dns.SRV {
	parts := strings.Fields(rec.Content)
	if len(parts) != 3 {
		log.Printf("Invalid SRV record format: %s", rec.Content)
		return nil
	}
	var weight, port uint16
	fmt.Sscanf(parts[0], "%d", &weight)
	fmt.Sscanf(parts[1], "%d", &port)
	return &dns.SRV{
		Hdr:      dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: rec.TTL},
		Priority: rec.Priority,
		Weight:   weight,
		Port:     port,
		Target:   parts[2],
	}
}
