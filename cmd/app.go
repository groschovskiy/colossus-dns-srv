package main

import (
	"log"
	"time"

	"colossus-dns/internal/ctl"
	"colossus-dns/internal/handlers"

	"github.com/miekg/dns"
)

func main() {
	db, err := ctl.InitDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	ctl.InitRecords()

	go func() {
		for {
			time.Sleep(3 * time.Second)
			if err := ctl.LoadRecords(db); err != nil {
				log.Fatalf("Failed to load records: %v", err)
			}
		}
	}()

	server := &dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", handlers.HandleDNSRequest)

	log.Println("Starting DNS server on :53")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
