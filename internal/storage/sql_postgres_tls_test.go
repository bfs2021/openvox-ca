// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/uptrace/bun/driver/pgdriver"
)

// pgTestCA is a throwaway CA minted per spec, so no key is ever committed.
type pgTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newPGTestCA(name string) *pgTestCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return &pgTestCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issueIntermediate returns a CA signed by ca rather than by itself, as the
// issuing CA of most real PKIs is.
func (ca *pgTestCA) issueIntermediate(name string) *pgTestCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return &pgTestCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issueServer returns a PEM certificate and key for a server answering to
// host, which may be a DNS name or an IP address.
func (ca *pgTestCA) issueServer(host string) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

var _ = Describe("PostgreSQL sql_tls_* configuration", func() {
	var (
		base   *tls.Config
		caFile string
	)

	BeforeEach(func() {
		// pgdriver falls back to PGHOST and PGPORT for a DSN that names no
		// host; empty them so the runner's environment cannot move the answer.
		GinkgoT().Setenv("PGHOST", "")
		GinkgoT().Setenv("PGPORT", "")
		// Every field loadBackendTLS can set, so a refactor that rebuilds the
		// config rather than cloning it cannot drop one unnoticed.
		base = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      x509.NewCertPool(),
			Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}},
		}
		// pgdriver reads a DSN's sslrootcert while parsing it, so a DSN that
		// names one needs a real file.
		caFile = filepath.Join(GinkgoT().TempDir(), "ca.pem")
		Expect(os.WriteFile(caFile, newPGTestCA("unit test CA").pem, 0o600)).To(Succeed())
	})

	// apply parses dsn and applies the files exactly as openSQLDB does.
	apply := func(dsn string) (*pgdriver.Config, error) {
		dsn = strings.ReplaceAll(dsn, "CAFILE", caFile)
		conf := pgdriver.NewConnector(pgdriver.WithDSN(dsn)).Config()
		return conf, applyPostgresTLS(conf, dsn, base)
	}

	DescribeTable("verifies the server against the host the driver dials",
		func(dsn, want string) {
			conf, err := apply(dsn)
			Expect(err).NotTo(HaveOccurred())
			Expect(conf.TLSConfig.ServerName).To(Equal(want))
			Expect(conf.TLSConfig.InsecureSkipVerify).To(BeFalse())
			Expect(conf.TLSConfig.VerifyConnection).To(BeNil())
			Expect(conf.TLSConfig.RootCAs).To(BeIdenticalTo(base.RootCAs))
			Expect(conf.TLSConfig.Certificates).To(Equal(base.Certificates))
			Expect(conf.TLSConfig.MinVersion).To(Equal(base.MinVersion))
		},
		Entry("a hostname", "postgres://u:p@db.example.com:5432/ca?sslmode=verify-full", "db.example.com"),
		Entry("a hostname on the default port", "postgres://u:p@db.example.com/ca?sslmode=verify-full", "db.example.com"),
		Entry("an IPv4 address", "postgres://u:p@192.0.2.10:5432/ca?sslmode=verify-full", "192.0.2.10"),
		Entry("an IPv6 address", "postgres://u:p@[2001:db8::10]:5432/ca?sslmode=verify-full", "2001:db8::10"),
		Entry("no host, so the driver's localhost default", "postgres://u:p@/ca?sslmode=verify-full", "localhost"),
		// pgdriver applies host= after the URL's host, so host= is what it
		// dials, and so what must be verified.
		Entry("a TCP host= overriding the URL's host", "postgres://u:p@decoy.example.com:5432/ca?host=real.example.com:5432&sslmode=verify-full", "real.example.com"),
	)

	It("follows PGHOST when the DSN names no host, as the driver does", func() {
		GinkgoT().Setenv("PGHOST", "pg.example.net")
		conf, err := apply("postgres://u:p@/ca?sslmode=verify-full")
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.TLSConfig.ServerName).To(Equal("pg.example.net"))
	})

	It("leaves the loaded configuration untouched for its next user", func() {
		_, err := apply("postgres://u:p@db.example.com/ca?sslmode=verify-ca")
		Expect(err).NotTo(HaveOccurred())
		Expect(base.ServerName).To(BeEmpty())
		Expect(base.InsecureSkipVerify).To(BeFalse())
		Expect(base.VerifyConnection).To(BeNil())
	})

	// The DSN's sslmode decides what is checked, as in libpq; the files only
	// supply what it is checked against.
	DescribeTable("checks what the DSN's sslmode asks for",
		func(mode string, withCA bool, want string) {
			if !withCA {
				base.RootCAs = nil
			}
			conf, err := apply("postgres://u:p@db.example.com/ca?sslmode=" + mode)
			Expect(err).NotTo(HaveOccurred())
			Expect(conf.TLSConfig.ServerName).To(Equal("db.example.com"))
			Expect(conf.TLSConfig.Certificates).To(Equal(base.Certificates), "the client certificate is sent whatever is checked")
			switch want {
			case "chain and name":
				Expect(conf.TLSConfig.InsecureSkipVerify).To(BeFalse())
				Expect(conf.TLSConfig.VerifyConnection).To(BeNil())
			case "chain only":
				Expect(conf.TLSConfig.InsecureSkipVerify).To(BeTrue())
				Expect(conf.TLSConfig.VerifyConnection).NotTo(BeNil())
			case "nothing":
				Expect(conf.TLSConfig.InsecureSkipVerify).To(BeTrue())
				Expect(conf.TLSConfig.VerifyConnection).To(BeNil())
			default:
				Fail("unknown expectation " + want)
			}
		},
		Entry("verify-full with a CA file", "verify-full", true, "chain and name"),
		Entry("verify-full with only a client certificate, against the system's CAs", "verify-full", false, "chain and name"),
		Entry("verify-ca with a CA file", "verify-ca", true, "chain only"),
		Entry("verify-ca with only a client certificate, against the system's CAs", "verify-ca", false, "chain only"),
		// libpq: "if a root CA file exists, the behavior of sslmode=require
		// will be the same as that of verify-ca".
		Entry("require with a CA file", "require", true, "chain only"),
		Entry("require with only a client certificate", "require", false, "nothing"),
	)

	Describe("the chain-only check installed for verify-ca", func() {
		var (
			trusted *pgTestCA
			check   func(tls.ConnectionState) error
		)

		BeforeEach(func() {
			trusted = newPGTestCA("trusted")
			base.RootCAs = x509.NewCertPool()
			base.RootCAs.AddCert(trusted.cert)
			conf, err := apply("postgres://u:p@db.example.com/ca?sslmode=verify-ca")
			Expect(err).NotTo(HaveOccurred())
			check = conf.TLSConfig.VerifyConnection
			Expect(check).NotTo(BeNil())
		})

		// presenting is what a server issued for host by ca hands over.
		presenting := func(ca *pgTestCA, host string) tls.ConnectionState {
			certPEM, _ := ca.issueServer(host)
			block, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		}

		It("accepts a certificate from the CA whatever name it carries", func() {
			Expect(check(presenting(trusted, "not-the-database.example"))).To(Succeed())
		})

		It("refuses a certificate from another CA", func() {
			err := check(presenting(newPGTestCA("stranger"), "db.example.com"))
			var unknown x509.UnknownAuthorityError
			Expect(errors.As(err, &unknown)).To(BeTrue(), "want an unknown-authority error, got: %v", err)
		})

		It("refuses a server that presents no certificate", func() {
			Expect(check(tls.ConnectionState{})).To(MatchError(ContainSubstring("no certificate")))
		})

		Context("when the server's certificate comes from an intermediate CA", func() {
			// Only the root is trusted, so the chain completes only through
			// the intermediate the server sends alongside its own certificate.
			var leaf, intermediate *x509.Certificate

			BeforeEach(func() {
				issuing := trusted.issueIntermediate("issuing")
				leaf = presenting(issuing, "db.example.com").PeerCertificates[0]
				intermediate = issuing.cert
			})

			It("accepts the chain through the intermediate the server presents", func() {
				Expect(check(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, intermediate}})).To(Succeed())
			})

			It("refuses the leaf when the server omits the intermediate", func() {
				err := check(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
				var unknown x509.UnknownAuthorityError
				Expect(errors.As(err, &unknown)).To(BeTrue(), "want an unknown-authority error, got: %v", err)
			})
		})
	})

	DescribeTable("refuses sql_tls_* files the DSN would ignore or contradict",
		func(dsn, reason string) {
			_, err := apply(dsn)
			Expect(err).To(MatchError(ContainSubstring(reason)))
		},
		Entry("no sslmode, so libpq's prefer", "postgres://u:p@db.example.com/ca", "defaults to prefer"),
		Entry("sslmode=disable", "postgres://u:p@db.example.com/ca?sslmode=disable", "sslmode=disable does not verify"),
		Entry("sslmode=allow", "postgres://u:p@db.example.com/ca?sslmode=allow", "sslmode=allow does not verify"),
		Entry("sslmode=prefer", "postgres://u:p@db.example.com/ca?sslmode=prefer", "sslmode=prefer does not verify"),
		Entry("the DSN's own sslrootcert", "postgres://u:p@db.example.com/ca?sslmode=verify-full&sslrootcert=CAFILE", "sets sslrootcert"),
		Entry("the DSN's own sslcert", "postgres://u:p@db.example.com/ca?sslmode=verify-full&sslcert=/c.pem", "sets sslcert"),
		Entry("the DSN's own sslkey", "postgres://u:p@db.example.com/ca?sslmode=verify-full&sslkey=/k.pem", "sets sslkey"),
	)

	DescribeTable("refuses a DSN with no single host to verify",
		func(dsn, reason string) {
			_, err := apply(dsn)
			Expect(err).To(MatchError(ContainSubstring(reason)))
		},
		Entry("a Unix socket named by host=", "postgres://u:p@/ca?host=/var/run/postgresql&sslmode=verify-full", "unix socket"),
		Entry("a unix:// DSN", "unix://u:p@ca/var/run/postgresql/.s.PGSQL.5432?sslmode=verify-full", "unix socket"),
		Entry("several hosts", "postgres://u:p@db1.example.com:5432,db2.example.com:5432/ca?sslmode=verify-full", "names several"),
		Entry("several hosts on the default port", "postgres://u:p@db1.example.com,db2.example.com/ca?sslmode=verify-full", "names several"),
		Entry("a port with no host", "postgres://u:p@:5432/ca?sslmode=verify-full", "cannot find the PostgreSQL host"),
		// pgdriver appends the default port only to a host with no colon in
		// it, so a bracketed IPv6 address without one reaches it portless.
		Entry("an IPv6 address with no port", "postgres://u:p@[2001:db8::10]/ca?sslmode=verify-full", "cannot find the PostgreSQL host"),
	)

	// Every refusal belongs to the sql_tls_* files alone: without them the
	// same DSNs open exactly as before. NewSQLBackend connects lazily, so
	// neither half dials anything.
	DescribeTable("refuses at open time only when sql_tls_* is set",
		func(dsn, reason string) {
			_, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: dsn, TLS: base})
			Expect(err).To(MatchError(ContainSubstring(reason)))

			b, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			Expect(b.Close()).To(Succeed())
		},
		Entry("a Unix socket", "postgres://u:p@/ca?host=/var/run/postgresql&sslmode=verify-full", "unix socket"),
		Entry("several hosts", "postgres://u:p@db1.example.com:5432,db2.example.com:5432/ca?sslmode=verify-full", "names several"),
		Entry("no sslmode", "postgres://u:p@db.example.com/ca", "defaults to prefer"),
		Entry("sslmode=prefer", "postgres://u:p@db.example.com/ca?sslmode=prefer", "does not verify"),
	)
})
