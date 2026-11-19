package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Kaivodev/servicekit/devcert"
)

func main() {
	dir := flag.String("out", "", "new output directory (must not exist)")
	domain := flag.String("trust-domain", "aipay.test", "development trust domain")
	services := flag.String("services", "backend,iam,payment,ledger,settlement,reconciliation,probe", "comma-separated service identities")
	signingServices := flag.String("signing-services", "", "subset of service identities that also need persistent development signing keys")
	days := flag.Int("days", 7, "certificate lifetime, 1-30 days")
	flag.Parse()
	if flag.NArg() != 0 || *days < 1 || *days > 30 {
		fmt.Fprintln(os.Stderr, "invalid development certificate arguments")
		os.Exit(1)
	}
	identities := strings.Split(*services, ",")
	var signers []string
	if *signingServices != "" {
		for _, name := range strings.Split(*signingServices, ",") {
			if !slices.Contains(identities, name) || slices.Contains(signers, name) {
				fmt.Fprintln(os.Stderr, "signing services must be a unique subset of certificate identities")
				os.Exit(1)
			}
			signers = append(signers, name)
		}
	}
	if err := devcert.Generate(*dir, *domain, identities, time.Duration(*days)*24*time.Hour); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(signers) != 0 {
		if err := generateSigningKeys(*dir, signers); err != nil {
			_ = os.RemoveAll(*dir)
			fmt.Fprintln(os.Stderr, "create development signing material failed")
			os.Exit(1)
		}
	}
	fmt.Println("Created development-only certificates in", *dir)
}
