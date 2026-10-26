package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aipay-dev/servicekit/devcert"
)

func main() {
	dir := flag.String("out", "", "new output directory (must not exist)")
	domain := flag.String("trust-domain", "aipay.test", "development trust domain")
	services := flag.String("services", "backend,iam,ledger,settlement,reconciliation,probe", "comma-separated service identities")
	days := flag.Int("days", 7, "certificate lifetime, 1-30 days")
	flag.Parse()
	if flag.NArg() != 0 || *days < 1 || *days > 30 {
		fmt.Fprintln(os.Stderr, "invalid development certificate arguments")
		os.Exit(1)
	}
	if err := devcert.Generate(*dir, *domain, strings.Split(*services, ","), time.Duration(*days)*24*time.Hour); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Created development-only certificates in", *dir)
}
