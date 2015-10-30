package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type certInfo struct {
	FileName string
	NotAfter time.Time
	CertName string
}

var pageHead = `
<html>
	<head>
		<style>
			p {
				font-size:18px;
			}

			.warning {
				background-color:#d32d27;
				color:white;
			}

			.row {
				padding:10px;
				border-radius:5px;
				font-family:sans-serif;
				margin:5px;
			}
		</style>
	</head>
	<body>
		<div style='margin:0 auto;max-width:870px;'>
`

// wg is used to pevent a webrequest from attempting to return information
// before the async directory scanner is finished.
var wg sync.WaitGroup

// dir is the directory passed in by the user
var dir string

// certInfos will contain all of the information about certs we find.
var certInfos []certInfo

// walkFunc is the walking function called by each file and directory
// found in the flag specified directory.
func walkFunc(path string, info os.FileInfo, err error) (e error) {
	if info.IsDir() {
		return
	}
	f, e := os.Open(path)
	// If we can't open it, forget about it.
	if e != nil {
		return
	}

	// isOpen will tell you whether or not we have found a BEGIN or
	// if we found an END. TRUE if we have found a BEGIN but no END.
	// FALSE if we have found nothing or END and no BEGIN.
	isOpen := false

	// tryCert
	tryCert := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()

		// Try to find certificates deep in files. Once we find a begin
		// certificate and an end certificate, try to parse it.
		if strings.Contains(text, "BEGIN CERTIFICATE-----") {
			tryCert = fmt.Sprintf("%s\n", strings.TrimSpace(text))
			isOpen = true
		} else if strings.Contains(text, "END CERTIFICATE-----") {
			// This is a peculiar state. We found an END without a begin.
			// Just ignore it and try again later.
			if !isOpen {
				tryCert = ""
			}
			tryCert = fmt.Sprintf("%s%s", tryCert, strings.TrimSpace(text))
			// Try to parse the certificate.
			p, _ := pem.Decode([]byte(tryCert))
			cert, err := x509.ParseCertificate(p.Bytes)
			if err == nil {
				c := *new(certInfo)
				c.NotAfter = cert.NotAfter
				c.FileName = path
				dnsNames := ""
				for _, dnsName := range cert.DNSNames {
					if len(dnsNames) == 0 {
						dnsNames = dnsName
					} else {
						dnsNames = fmt.Sprintf("%s, %s", dnsNames, dnsName)
					}
				}
				c.CertName = dnsNames
				certInfos = append(certInfos, c)
			}
			isOpen = false
		} else {
			if isOpen {
				tryCert = fmt.Sprintf("%s%s\n", tryCert, strings.TrimSpace(text))
			}
		}
	}
	return
}
func getResults(w http.ResponseWriter, r *http.Request) {
	wg.Wait()
	w.Write([]byte(pageHead))
	for _, cert := range certInfos {
		certClass := ""
		yrFromNow := time.Now().AddDate(0, 1, 0)
		if cert.NotAfter.Before(yrFromNow) {
			certClass = "warning"
		}
		htmlRow := fmt.Sprintf("<div class='row %s'><div>%s</div><div>%s</div><div>%s</div></div>", certClass, cert.NotAfter, html.EscapeString(cert.FileName), html.EscapeString(cert.CertName))
		w.Write([]byte(htmlRow))
	}
	w.Write([]byte("</div></body></html>"))
}
func main() {
	flag.StringVar(&dir, "d", "", "search `directory` for certificates")
	flag.Parse()

	if len(dir) == 0 {
		log.Fatalf("Must supply a directory to search for ceritficates.")
	}
	go func() {
		for {
			wg.Add(1)
			certInfos = *new([]certInfo)

			// walk through each file or directory and accumulate all the certificates
			filepath.Walk(dir, walkFunc)
			wg.Done()
			time.Sleep(time.Minute)
		}
	}()
	http.HandleFunc("/", getResults)
	http.ListenAndServe(":8000", nil)
}
