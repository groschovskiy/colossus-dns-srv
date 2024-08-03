package ctl

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
)

func InitDatabase() (*sql.DB, error) {
	mysql.RegisterTLSConfig("tidb", &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: os.Getenv("TIDB_HOST"),
	})

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?tls=tidb",
		os.Getenv("TIDB_USER"),
		os.Getenv("TIDB_PASSWORD"),
		os.Getenv("TIDB_HOST"),
		os.Getenv("TIDB_PORT"),
		os.Getenv("TIDB_DATABASE")))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	return db, nil
}

func LoadRecords(db *sql.DB) error {
	rows, err := db.Query("SELECT name, type, content, ttl, priority, geo_continent FROM dns_records")
	if err != nil {
		return err
	}
	defer rows.Close()

	recordLock.Lock()
	defer recordLock.Unlock()

	newRecords := make(map[string][]DNSRecord)

	for rows.Next() {
		var r DNSRecord
		var recordType string
		err := rows.Scan(&r.Name, &recordType, &r.Content, &r.TTL, &r.Priority, &r.GeoContinent)
		if err != nil {
			return err
		}
		r.Type = dns.StringToType[recordType]
		r.Name = dns.Fqdn(r.Name)

		switch r.Type {
		case dns.TypeCNAME:
			r.Content = dns.Fqdn(r.Content)
		case dns.TypeMX:
			parts := strings.Fields(r.Content)
			if len(parts) == 2 {
				preference, err := strconv.ParseUint(parts[0], 10, 16)
				if err == nil {
					r.Priority = uint16(preference)
					r.Content = dns.Fqdn(parts[1])
				} else {
					r.Content = fmt.Sprintf("%d %s", r.Priority, dns.Fqdn(r.Content))
				}
			} else if len(parts) == 1 {
				r.Content = fmt.Sprintf("%d %s", r.Priority, dns.Fqdn(r.Content))
			}
		case dns.TypeSRV:
			parts := strings.Fields(r.Content)
			if len(parts) == 3 {
				r.Content = fmt.Sprintf("%s %s %s", parts[0], parts[1], dns.Fqdn(parts[2]))
			}
		}

		newRecords[r.Name] = append(newRecords[r.Name], r)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	records = newRecords
	return nil
}
