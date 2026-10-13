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

package openbao

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openbao/openbao/api/v2"
)

// reportedNames is every variable logEnvironment can report: the
// envVariables table plus BAO_SKIP_VERIFY, which has a line of its own.
func reportedNames() []string {
	names := []string{api.EnvVaultSkipVerify}
	for _, v := range envVariables {
		names = append(names, v.name)
	}
	sort.Strings(names)
	return names
}

// newClient reports the SDK environment variables it was built under. Every
// spec starts from an environment with none of them, whatever the developer's
// or CI's shell holds, and sets only what it is about.
var _ = Describe("newClient's report of the OpenBao environment", func() {
	var (
		buf bytes.Buffer
		cfg Config
	)

	// unset removes name for this spec only: GinkgoT().Setenv records the
	// original value for restoration, and the Unsetenv that follows makes it
	// absent rather than empty — an empty BAO_ variable is not the same as a
	// missing one to the SDK, since it masks the VAULT_ fallback.
	unset := func(name string) {
		GinkgoT().Setenv(name, "")
		Expect(os.Unsetenv(name)).To(Succeed())
	}

	BeforeEach(func() {
		for _, n := range reportedNames() {
			unset(n)
			unset(api.UpstreamVariableName(n))
		}

		buf.Reset()
		// slog.SetDefault also points the log package at the new handler, and
		// restoring the original handler does not undo that, so restore the
		// log package's writer and flags as well.
		orig, origWriter, origFlags := slog.Default(), log.Writer(), log.Flags()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		DeferCleanup(func() {
			slog.SetDefault(orig)
			log.SetOutput(origWriter)
			log.SetFlags(origFlags)
		})

		cfg = Config{Addr: "https://openbao.invalid:8200", AuthMethod: AuthAppRole}
	})

	build := func() *api.Client {
		client, err := newClient(cfg)
		Expect(err).NotTo(HaveOccurred())
		return client
	}

	// warnLine and infoLine match a whole generic record, so a line with the
	// right variable under the wrong message, or without its effect, fails.
	warnLine := func(variable string) string {
		return `level=WARN msg="OpenBao client setting taken from the environment" variable=` +
			regexp.QuoteMeta(variable) + ` effect="[^"]+"`
	}
	infoLine := func(variable, setting string) string {
		if strings.Contains(setting, " ") {
			setting = strconv.Quote(setting) // as slog's TextHandler writes it
		}
		return `level=INFO msg="OpenBao environment variable has no effect" variable=` +
			regexp.QuoteMeta(variable) + ` superseded_by=` + regexp.QuoteMeta(setting) + `\n`
	}

	// newCert returns a self-signed certificate and its key. ConfigureTLS
	// only needs to parse what it is given; nothing connects.
	newCert := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		cert, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return cert, key
	}

	writePEM := func(name, blockType string, der []byte) string {
		path := filepath.Join(GinkgoT().TempDir(), name)
		Expect(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600)).To(Succeed())
		return path
	}

	// writeCA writes a fresh CA certificate and returns its path and the
	// certificate itself.
	writeCA := func() (string, *x509.Certificate) {
		cert, _ := newCert("openbao test CA")
		return writePEM("ca.pem", "CERTIFICATE", cert.Raw), cert
	}

	// writeKeyPair writes a client certificate and key and returns their paths.
	writeKeyPair := func() (string, string) {
		cert, key := newCert("openbao test client")
		der, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		return writePEM("client.pem", "CERTIFICATE", cert.Raw), writePEM("client.key", "PRIVATE KEY", der)
	}

	It("logs nothing when no variable is set", func() {
		build()
		Expect(buf.String()).To(BeEmpty(),
			"a warning on every clean start is noise, and noise is how a real one stops being read")
	})

	// skipVerifyLine matches the start of the dedicated record, so a generic
	// "taken from the environment" warning cannot satisfy these specs.
	const skipVerifyLine = `level=WARN msg="OpenBao server certificate verification is OFF[^"]*" `

	Context("when server certificate verification is switched off", func() {
		It("reports BAO_SKIP_VERIFY on a warning line of its own", func() {
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "true")
			build()
			// Anchored at the end: with no CA file there is nothing to override.
			Expect(buf.String()).To(MatchRegexp(skipVerifyLine + `variable=BAO_SKIP_VERIFY\n`))
			Expect(buf.String()).NotTo(ContainSubstring("level=ERROR"),
				"warning level, so it does not trip alerting keyed on errors")
		})

		It("reports VAULT_SKIP_VERIFY under its own name", func() {
			GinkgoT().Setenv("VAULT_SKIP_VERIFY", "true")
			build()
			Expect(buf.String()).To(MatchRegexp(skipVerifyLine + `variable=VAULT_SKIP_VERIFY\n`))
		})

		// The configured CA file cannot turn verification back on: the SDK's
		// ConfigureTLS only ever sets InsecureSkipVerify, never clears it.
		It("still reports it when openbao.tls_ca_file is set, naming what it overrides", func() {
			cfg.TLSCAFile, _ = writeCA()
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "1")
			build()
			Expect(buf.String()).To(MatchRegexp(skipVerifyLine + `variable=BAO_SKIP_VERIFY overrides=openbao\.tls_ca_file`))
		})
	})

	Context("when a SKIP_VERIFY variable leaves verification on", func() {
		It("stays quiet for an explicit false", func() {
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "false")
			build()
			Expect(buf.String()).To(BeEmpty())
		})

		// The SDK reads a present BAO_ variable even when it is empty, which
		// masks the VAULT_ one; the report must follow that reading.
		It("stays quiet when an empty BAO_SKIP_VERIFY masks VAULT_SKIP_VERIFY", func() {
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "")
			GinkgoT().Setenv("VAULT_SKIP_VERIFY", "true")
			build()
			Expect(buf.String()).To(BeEmpty())
		})
	})

	It("warns about a proxy by name, without logging its value", func() {
		GinkgoT().Setenv("BAO_PROXY_ADDR", "http://proxyuser:proxy-secret@proxy.invalid:3128")
		build()
		Expect(buf.String()).To(MatchRegexp(warnLine("BAO_PROXY_ADDR")))
		Expect(buf.String()).NotTo(ContainSubstring("proxy-secret"))
		Expect(buf.String()).NotTo(ContainSubstring("proxy.invalid"))
	})

	It("warns about BAO_TOKEN by name, without logging the token", func() {
		GinkgoT().Setenv("BAO_TOKEN", "s.ambient-token-value")
		build()
		Expect(buf.String()).To(MatchRegexp(warnLine("BAO_TOKEN")))
		Expect(buf.String()).NotTo(ContainSubstring("ambient-token-value"))
	})

	// With token auth the token file is set on the client before the first
	// request, so an ambient token is never sent.
	It("reports BAO_TOKEN as superseded under token auth, without logging the token", func() {
		cfg.AuthMethod = AuthToken
		GinkgoT().Setenv("VAULT_TOKEN", "s.ambient-token-value")
		build()
		Expect(buf.String()).To(MatchRegexp(infoLine("VAULT_TOKEN", "openbao.token_file")))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(buf.String()).NotTo(ContainSubstring("ambient-token-value"))
	})

	It("reports BAO_ADDR as superseded by openbao.addr, not as an override", func() {
		GinkgoT().Setenv("BAO_ADDR", "https://elsewhere.invalid:8200")
		build()
		Expect(buf.String()).To(MatchRegexp(infoLine("BAO_ADDR", "openbao.addr")))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(buf.String()).NotTo(ContainSubstring("elsewhere.invalid"))
	})

	// BAO_AGENT_ADDR is the address variable that does win: NewClient sends
	// every request to AgentAddress when it is set, and openvox-ca only sets
	// Address.
	It("warns that BAO_AGENT_ADDR overrides openbao.addr", func() {
		GinkgoT().Setenv("BAO_AGENT_ADDR", "https://agent.invalid:8100")
		build()
		Expect(buf.String()).To(MatchRegexp(warnLine("BAO_AGENT_ADDR") + ` overrides=openbao\.addr`))
	})

	// The supersession is a prediction made from cfg alone, so each case
	// also checks the trust pool of the client that was actually built: if
	// the SDK ever merged the pools instead of rebuilding them, the log line
	// would be wrong and these specs would say so. Each of the three ways
	// the environment can supply a CA gets both cases, so a row wired to the
	// wrong predicate fails too.
	Context("with a CA from the environment", func() {
		var envCA *x509.Certificate

		// setCA supplies a fresh CA through variable, in the form it takes.
		setCA := func(variable string) {
			path, cert := writeCA()
			envCA = cert
			switch variable {
			case "BAO_CACERT":
				GinkgoT().Setenv(variable, path)
			case "BAO_CACERT_BYTES":
				GinkgoT().Setenv(variable, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
			case "BAO_CAPATH":
				GinkgoT().Setenv(variable, filepath.Dir(path))
			default:
				Fail("no CA form for " + variable)
			}
		}

		trusts := func(client *api.Client) bool {
			_, err := envCA.Verify(x509.VerifyOptions{Roots: client.CloneConfig().TLSConfig().RootCAs})
			return err == nil
		}

		DescribeTable("warns, and trusts that CA, when openbao.tls_ca_file is unset",
			func(variable string) {
				setCA(variable)
				client := build()
				Expect(buf.String()).To(MatchRegexp(warnLine(variable)))
				Expect(trusts(client)).To(BeTrue())
			},
			Entry(nil, "BAO_CACERT"),
			Entry(nil, "BAO_CACERT_BYTES"),
			Entry(nil, "BAO_CAPATH"),
		)

		DescribeTable("reports it as superseded, and no longer trusts it, when openbao.tls_ca_file is set",
			func(variable string) {
				setCA(variable)
				cfg.TLSCAFile, _ = writeCA()
				client := build()
				Expect(buf.String()).To(MatchRegexp(infoLine(variable, "openbao.tls_ca_file")))
				Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
				Expect(trusts(client)).To(BeFalse())
			},
			Entry(nil, "BAO_CACERT"),
			Entry(nil, "BAO_CACERT_BYTES"),
			Entry(nil, "BAO_CAPATH"),
		)
	})

	// The environment can supply a client certificate as files or as PEM
	// bytes; both forms get every case. As with the CA, each case also checks
	// the certificate the built client actually presents, since the
	// supersession is predicted from cfg alone.
	Context("with a client certificate from the environment", func() {
		var (
			certVar, keyVar string
			envCertDER      []byte
		)

		// certDER reads back the DER of the certificate in a PEM file.
		certDER := func(path string) []byte {
			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(data)
			Expect(block).NotTo(BeNil())
			return block.Bytes
		}

		// presented returns the DER of the certificate the built client would
		// present to OpenBao.
		presented := func(client *api.Client) []byte {
			getCert := client.CloneConfig().TLSConfig().GetClientCertificate
			Expect(getCert).NotTo(BeNil(), "the built client presents no client certificate")
			cert, err := getCert(&tls.CertificateRequestInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.Certificate).NotTo(BeEmpty())
			return cert.Certificate[0]
		}

		setClientCert := func(bytesForm bool) {
			certPath, keyPath := writeKeyPair()
			envCertDER = certDER(certPath)
			certVar, keyVar = "BAO_CLIENT_CERT", "BAO_CLIENT_KEY"
			certValue, keyValue := certPath, keyPath
			if bytesForm {
				certVar, keyVar = "BAO_CLIENT_CERT_BYTES", "BAO_CLIENT_KEY_BYTES"
				certPEM, err := os.ReadFile(certPath)
				Expect(err).NotTo(HaveOccurred())
				keyPEM, err := os.ReadFile(keyPath)
				Expect(err).NotTo(HaveOccurred())
				certValue, keyValue = string(certPEM), string(keyPEM)
			}
			GinkgoT().Setenv(certVar, certValue)
			GinkgoT().Setenv(keyVar, keyValue)
		}

		DescribeTable("warns, and presents that certificate, when openvox-ca configures no TLS files",
			func(bytesForm bool) {
				setClientCert(bytesForm)
				client := build()
				Expect(buf.String()).To(MatchRegexp(warnLine(certVar)))
				Expect(buf.String()).To(MatchRegexp(warnLine(keyVar)))
				Expect(presented(client)).To(Equal(envCertDER))
			},
			Entry("as files", false),
			Entry("as PEM bytes", true),
		)

		// ConfigureTLS replaces the client certificate only when it is given
		// one, so a CA file alone leaves the environment's certificate in use.
		DescribeTable("still warns, and still presents it, when only openbao.tls_ca_file is set",
			func(bytesForm bool) {
				setClientCert(bytesForm)
				cfg.TLSCAFile, _ = writeCA()
				client := build()
				Expect(buf.String()).To(MatchRegexp(warnLine(certVar)))
				Expect(buf.String()).To(MatchRegexp(warnLine(keyVar)))
				Expect(presented(client)).To(Equal(envCertDER))
			},
			Entry("as files", false),
			Entry("as PEM bytes", true),
		)

		DescribeTable("reports it as superseded, and presents openvox-ca's instead, when openbao.tls_cert_file and tls_key_file are set",
			func(bytesForm bool) {
				setClientCert(bytesForm)
				cfg.TLSCertFile, cfg.TLSKeyFile = writeKeyPair()
				client := build()
				Expect(buf.String()).To(MatchRegexp(infoLine(certVar, "openbao.tls_cert_file")))
				Expect(buf.String()).To(MatchRegexp(infoLine(keyVar, "openbao.tls_cert_file")))
				Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
				Expect(presented(client)).To(Equal(certDER(cfg.TLSCertFile)))
			},
			Entry("as files", false),
			Entry("as PEM bytes", true),
		)
	})

	// newClient sets the request timeout after the SDK has read the
	// environment, so BAO_CLIENT_TIMEOUT never reaches the built client.
	It("reports BAO_CLIENT_TIMEOUT as superseded, and the client keeps the built-in timeout", func() {
		GinkgoT().Setenv("BAO_CLIENT_TIMEOUT", "1h")
		client := build()
		Expect(buf.String()).To(MatchRegexp(infoLine("BAO_CLIENT_TIMEOUT", "the signer's built-in request timeout")))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(client.ClientTimeout()).To(Equal(cfg.loginTimeout()))
	})

	// These two are read from the SDK's resulting config rather than the
	// raw value, so a value that leaves the default in place stays quiet.
	DescribeTable("a boolean variable",
		func(name, value string, warns bool) {
			GinkgoT().Setenv(name, value)
			build()
			if warns {
				Expect(buf.String()).To(MatchRegexp(warnLine(name)))
			} else {
				Expect(buf.String()).To(BeEmpty())
			}
		},
		Entry("BAO_SRV_LOOKUP=true warns", "BAO_SRV_LOOKUP", "true", true),
		Entry("BAO_SRV_LOOKUP=false stays quiet", "BAO_SRV_LOOKUP", "false", false),
		Entry("BAO_DISABLE_REDIRECTS=true warns", "BAO_DISABLE_REDIRECTS", "true", true),
		Entry("BAO_DISABLE_REDIRECTS=false stays quiet", "BAO_DISABLE_REDIRECTS", "false", false),
	)

	// The variables with no openvox-ca equivalent each warn on their own;
	// the troubleshooting entry in docs/openbao-transit.md sends operators
	// looking for these lines.
	DescribeTable("a variable with no openvox-ca equivalent warns",
		func(name, value string) {
			GinkgoT().Setenv(name, value)
			build()
			Expect(buf.String()).To(MatchRegexp(warnLine(name)))
		},
		Entry(nil, "BAO_TLS_SERVER_NAME", "openbao.example"),
		Entry(nil, "BAO_HTTP_PROXY", "http://proxy.invalid:3128"),
		Entry(nil, "BAO_MAX_RETRIES", "5"),
		Entry(nil, "BAO_RATE_LIMIT", "10"),
		Entry(nil, "BAO_NAMESPACE", "team-a"),
		Entry(nil, "VAULT_NAMESPACE", "team-a"),
		Entry(nil, "BAO_WRAP_TTL", "5m"),
	)

	It("ignores a variable set to the empty string, as the SDK does", func() {
		GinkgoT().Setenv("BAO_NAMESPACE", "")
		GinkgoT().Setenv("VAULT_NAMESPACE", "team-a")
		build()
		Expect(buf.String()).To(BeEmpty())
	})

	// The SDK's own message for this case says nothing about the
	// environment, so without the names an operator has nowhere to look.
	It("names the variables set, without their values, when the environment stops the client being built", func() {
		certPath, _ := writeKeyPair()
		GinkgoT().Setenv("VAULT_CLIENT_CERT", certPath)
		_, err := newClient(cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("OpenBao environment variables set: VAULT_CLIENT_CERT"))
		Expect(err.Error()).NotTo(ContainSubstring(certPath))
		Expect(err.Error()).To(ContainSubstring("both client cert and client key must be provided"))
		Expect(err.Error()).NotTo(ContainSubstring("value withheld"))
	})

	// An unencoded "/" in a password ends the authority early, so url.Parse
	// reads "pa" as a port and its error quotes the URL and that port. The
	// SDK parses the proxy while reading the environment and the agent
	// address in NewClient, so each build site gets a case.
	DescribeTable("withholds a malformed URL from the environment, password included",
		func(variable, site string) {
			GinkgoT().Setenv(variable, "http://someuser:pa/ss-secret@host.invalid:3128")
			_, err := newClient(cfg)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(site))
			Expect(err.Error()).To(ContainSubstring("OpenBao environment variables set: " + variable))
			Expect(err.Error()).To(ContainSubstring(variable + ": parse of the URL failed (value withheld)"))
			for _, part := range []string{"someuser", "ss-secret", "pa/", `":pa"`, "host.invalid"} {
				Expect(err.Error()).NotTo(ContainSubstring(part))
			}
		},
		Entry("BAO_PROXY_ADDR, read with the environment", "BAO_PROXY_ADDR", "building default OpenBao client config"),
		Entry("BAO_HTTP_PROXY, read with the environment", "BAO_HTTP_PROXY", "building default OpenBao client config"),
		Entry("VAULT_PROXY_ADDR, under its own name", "VAULT_PROXY_ADDR", "building default OpenBao client config"),
		Entry("BAO_AGENT_ADDR, parsed by NewClient", "BAO_AGENT_ADDR", "creating OpenBao client"),
	)

	// BAO_PROXY_ADDR supersedes BAO_HTTP_PROXY, so when both are set the
	// error must blame the one the SDK actually parsed.
	It("names BAO_PROXY_ADDR, not BAO_HTTP_PROXY, when both are set and it is the malformed one", func() {
		GinkgoT().Setenv("BAO_HTTP_PROXY", "http://proxy.invalid:3128")
		GinkgoT().Setenv("BAO_PROXY_ADDR", "http://someuser:pa/ss-secret@host.invalid:3128")
		_, err := newClient(cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("BAO_PROXY_ADDR: parse of the URL failed"))
		Expect(err.Error()).NotTo(ContainSubstring("BAO_HTTP_PROXY: parse"))
		Expect(err.Error()).To(ContainSubstring("OpenBao environment variables set: BAO_HTTP_PROXY, BAO_PROXY_ADDR)"))
	})

	// The SDK's message names BAO_SKIP_VERIFY whichever spelling was set,
	// so the suffix is what points at the variable actually in use.
	It("names VAULT_SKIP_VERIFY when an unparsable value stops the client being built", func() {
		GinkgoT().Setenv("VAULT_SKIP_VERIFY", "maybe")
		_, err := newClient(cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("OpenBao environment variables set: VAULT_SKIP_VERIFY)"))
		// Not a URL error, so withholdURL must pass the SDK's message through
		// rather than relabel it as a proxy failure.
		Expect(err.Error()).To(ContainSubstring("could not parse BAO_SKIP_VERIFY"))
		Expect(err.Error()).NotTo(ContainSubstring("value withheld"))
	})

	// The withholding is for values the environment supplied; a bad
	// openbao.addr is the operator's own configuration and keeps its detail.
	It("keeps the detail when the malformed URL is openbao.addr", func() {
		cfg.Addr = "http://openbao.invalid:bad-port"
		_, err := newClient(cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("bad-port"))
		Expect(err.Error()).NotTo(ContainSubstring("value withheld"))
	})
})

// The operator-facing table and envVariables both enumerate what the SDK
// reads. These specs hold the three in step, so an SDK upgrade that starts
// reading another variable fails here rather than going unreported.
var _ = Describe("the OpenBao environment enumeration", func() {
	It("matches the table in docs/openbao-transit.md", func() {
		doc, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "openbao-transit.md"))
		Expect(err).NotTo(HaveOccurred())

		_, section, found := strings.Cut(string(doc), "\n### OpenBao client environment variables\n")
		Expect(found).To(BeTrue(), "the section heading moved; update this spec and the anchor in client.go")
		section, _, _ = strings.Cut(section, "\n#")

		var documented []string
		name := regexp.MustCompile("`(BAO_[A-Z_]+)`")
		for _, line := range strings.Split(section, "\n") {
			if !strings.HasPrefix(line, "| `BAO_") {
				continue
			}
			firstCell := strings.Split(line, "|")[1]
			for _, m := range name.FindAllStringSubmatch(firstCell, -1) {
				documented = append(documented, m[1])
			}
		}
		sort.Strings(documented)
		Expect(documented).To(Equal(reportedNames()))
	})

	It("matches every ReadBaoVariable call in the SDK source go.mod pins", func() {
		dir := sdkSourceDir()

		// Read by plugin_helpers.go, which only OpenBao plugins call; the
		// client newClient builds never reaches it.
		pluginOnly := map[string]bool{
			"BAO_PLUGIN_AUTOMTLS_ENABLED": true,
			"BAO_PLUGIN_METADATA_MODE":    true,
			"BAO_UNWRAP_TOKEN":            true,
		}

		fset := token.NewFileSet()
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		Expect(err).NotTo(HaveOccurred())
		consts := map[string]string{}
		var parsed []*ast.File
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, f, nil, 0)
			Expect(err).NotTo(HaveOccurred())
			parsed = append(parsed, file)
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if i < len(vs.Values) {
							if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								consts[id.Name], _ = strconv.Unquote(lit.Value)
							}
						}
					}
				}
			}
		}
		Expect(consts).NotTo(BeEmpty(), "found no constants under %s", dir)

		read := map[string]bool{}
		for _, file := range parsed {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok || (fn.Name != "ReadBaoVariable" && fn.Name != "LookupBaoVariable") {
					return true
				}
				switch arg := call.Args[0].(type) {
				case *ast.Ident:
					value, ok := consts[arg.Name]
					Expect(ok).To(BeTrue(), "%s reads %s, which this spec cannot resolve", fset.Position(call.Pos()), arg.Name)
					read[value] = true
				case *ast.BasicLit:
					value, _ := strconv.Unquote(arg.Value)
					read[value] = true
				default:
					Fail("cannot resolve the argument to " + fn.Name + " at " + fset.Position(call.Pos()).String())
				}
				return true
			})
		}

		var sdk []string
		for name := range read {
			if !pluginOnly[name] {
				sdk = append(sdk, name)
			}
		}
		sort.Strings(sdk)
		Expect(sdk).To(Equal(reportedNames()),
			"the SDK reads a different set of variables: update envVariables and the docs table together")
	})
})

// sdkSourceNeeds is the failure message's account of what the SDK-source
// spec depends on outside the repository.
const sdkSourceNeeds = "the SDK-source spec reads the OpenBao client library source that go.mod pins, " +
	"so it needs the go command on PATH and the module in the module cache. It fails rather than " +
	"skips without them, because a skipped guard would let an SDK upgrade through unchecked"

// sdkSourceDir asks the go command where the pinned api/v2 module lives. Its
// environment has GIT_* stripped, as AGENTS.md requires of anything that
// might run git.
func sdkSourceDir() string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/openbao/openbao/api/v2")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, err := cmd.Output()
	var stderr []byte
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr = exitErr.Stderr
	}
	Expect(err).NotTo(HaveOccurred(), "%s.\ngo list: %s", sdkSourceNeeds, strings.TrimSpace(string(stderr)))
	dir := strings.TrimSpace(string(out))
	Expect(dir).NotTo(BeEmpty(), "%s.\ngo list printed no directory, so the module is not in the cache; run go mod download", sdkSourceNeeds)
	return dir
}
