package ctl

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os"

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
	rows, err := db.Query("SELECT name, type, content, ttl, priority FROM dns_records")
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
		err := rows.Scan(&r.Name, &recordType, &r.Content, &r.TTL, &r.Priority)
		if err != nil {
			return err
		}
		r.Type = dns.StringToType[recordType]
		r.Name = dns.Fqdn(r.Name)
		if r.Type == dns.TypeCNAME {
			r.Content = dns.Fqdn(r.Content)
		}
		newRecords[r.Name] = append(newRecords[r.Name], r)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	records = newRecords
	return nil
}
