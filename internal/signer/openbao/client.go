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
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/openbao/openbao/api/v2"
)

// newClient builds an OpenBao API client from cfg. TLS is configured via the
// SDK's own ConfigureTLS (same file-path shape as internal/storage/spec.go's
// loadBackendTLS); all three of TLSCAFile/TLSCertFile/TLSKeyFile may be empty
// to use the platform default trust store with no client certificate.
//
// api.DefaultConfig and api.NewClient also read the SDK's BAO_* (and VAULT_*)
// environment variables. That is deliberate — the administrator decides —
// but some of them override cfg, so logEnvironment reports every one in
// effect once the client is built. When the environment stops the client
// being built at all, the error names the variables that were set instead,
// since the SDK's own message does not always say where its input came from,
// and withholds any URL the environment supplied (see withholdURL).
func newClient(cfg Config) (*api.Client, error) {
	openBaoCfg := api.DefaultConfig()
	if openBaoCfg.Error != nil {
		// The only URL ReadEnvironment parses is the proxy's.
		return nil, fmt.Errorf("building default OpenBao client config%s: %w",
			envVariablesSetSuffix(), withholdURL(openBaoCfg.Error, proxyVariable()))
	}
	openBaoCfg.Address = cfg.Addr
	openBaoCfg.Timeout = cfg.loginTimeout()

	if cfg.TLSCAFile != "" || cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		tlsCfg := &api.TLSConfig{
			CACert:     cfg.TLSCAFile,
			ClientCert: cfg.TLSCertFile,
			ClientKey:  cfg.TLSKeyFile,
		}
		if err := openBaoCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configuring OpenBao client TLS: %w", err)
		}
	}

	client, err := api.NewClient(openBaoCfg)
	if err != nil {
		// NewClient parses BAO_AGENT_ADDR when it is set, openbao.addr when not.
		var variable string
		if openBaoCfg.AgentAddress != "" {
			variable = envSpelling(api.EnvVaultAgentAddr)
		}
		return nil, fmt.Errorf("creating OpenBao client%s: %w",
			envVariablesSetSuffix(), withholdURL(err, variable))
	}
	logEnvironment(cfg, openBaoCfg)
	return client, nil
}

// envVariable is one environment variable the SDK reads into the client
// newClient builds. The table in docs/openbao-transit.md
// (#openbao-client-environment-variables) says the same to operators. Specs
// in client_env_test.go hold both in step with each other and with the
// ReadBaoVariable calls in the SDK source go.mod pins (v2.7.1 when written).
type envVariable struct {
	// name is the BAO_ spelling. The SDK falls back to the VAULT_ one when
	// the BAO_ one is absent from the environment.
	name string
	// effect says what the variable does to the signer's connection.
	effect string
	// overrides names the openvox-ca setting the variable takes the place
	// of while it is in effect, or is empty when there is none.
	overrides string
	// supersededBy returns the openvox-ca setting that leaves the variable
	// without effect under cfg, or "" when the variable is in effect. Nil
	// means the environment always decides.
	supersededBy func(cfg Config) string
	// inEffect reports, from the SDK's resulting config, whether the value
	// changed anything. Nil means any value the SDK reads is in effect.
	inEffect func(c *api.Config) bool
}

// envVariables lists every variable the SDK reads on the signer's behalf,
// apart from BAO_SKIP_VERIFY, which logEnvironment reports on its own line.
var envVariables = []envVariable{
	{
		name:         api.EnvVaultAddress,
		effect:       "OpenBao server address",
		supersededBy: always("openbao.addr"),
	},
	{
		name:      api.EnvVaultAgentAddr,
		effect:    "sends every request to this address instead",
		overrides: "openbao.addr",
	},
	{
		name:         api.EnvVaultClientTimeout,
		effect:       "per-request timeout",
		supersededBy: always("the signer's built-in request timeout"),
	},
	{
		name:         api.EnvVaultCACert,
		effect:       "adds CA certificates trusted for the OpenBao server",
		supersededBy: caFileSet,
	},
	{
		name:         api.EnvVaultCACertBytes,
		effect:       "adds CA certificates trusted for the OpenBao server",
		supersededBy: caFileSet,
	},
	{
		name:         api.EnvVaultCAPath,
		effect:       "adds CA certificates trusted for the OpenBao server",
		supersededBy: caFileSet,
	},
	{
		name:         api.EnvVaultClientCert,
		effect:       "client certificate presented to OpenBao",
		supersededBy: clientCertSet,
	},
	{
		name:         api.EnvVaultClientCertBytes,
		effect:       "client certificate presented to OpenBao",
		supersededBy: clientCertSet,
	},
	{
		name:         api.EnvVaultClientKey,
		effect:       "client certificate presented to OpenBao",
		supersededBy: clientCertSet,
	},
	{
		name:         api.EnvVaultClientKeyBytes,
		effect:       "client certificate presented to OpenBao",
		supersededBy: clientCertSet,
	},
	{
		name:   api.EnvVaultTLSServerName,
		effect: "server name sent in TLS SNI and checked against the OpenBao certificate",
	},
	{
		name:   api.EnvHTTPProxy,
		effect: "proxy every request goes through, unless BAO_PROXY_ADDR is also set",
	},
	{
		name:   api.EnvVaultProxyAddr,
		effect: "proxy every request goes through",
	},
	{
		name:   api.EnvVaultMaxRetries,
		effect: "retries after a 5xx response",
	},
	{
		name:   api.EnvRateLimit,
		effect: "client-side request rate limit",
	},
	{
		name:     api.EnvVaultSRVLookup,
		effect:   "resolves the server through DNS SRV records when openbao.addr has no port",
		inEffect: func(c *api.Config) bool { return c.SRVLookup },
	},
	{
		name:     api.EnvVaultDisableRedirects,
		effect:   "stops the client following a redirect from OpenBao",
		inEffect: func(c *api.Config) bool { return c.DisableRedirects },
	},
	{
		name:   api.EnvVaultNamespace,
		effect: "namespace sent with every request, login and signing included",
	},
	{
		name:   api.EnvVaultToken,
		effect: "token sent with the first login request, until the login replaces it",
		supersededBy: func(cfg Config) string {
			if cfg.AuthMethod == AuthToken {
				return "openbao.token_file"
			}
			return ""
		},
	},
	{
		name:   api.EnvVaultWrapTTL,
		effect: "asks OpenBao to wrap every response, which the signer cannot use",
	},
}

func always(setting string) func(Config) string {
	return func(Config) string { return setting }
}

// caFileSet: ConfigureTLS rebuilds the trust pool from openbao.tls_ca_file,
// discarding whatever the environment added to it.
func caFileSet(cfg Config) string {
	if cfg.TLSCAFile != "" {
		return "openbao.tls_ca_file"
	}
	return ""
}

// clientCertSet: ConfigureTLS replaces the client certificate only when it is
// given one, so openbao.tls_ca_file alone leaves the environment's in place.
func clientCertSet(cfg Config) string {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		return "openbao.tls_cert_file"
	}
	return ""
}

// logEnvironment reports the SDK environment variables behind the client
// newClient has just built: one warning for each in effect, one info line
// for each that openvox-ca's configuration supersedes, and a warning of its
// own, with its own message, when server certificate verification is off.
// That one stays at warning level rather than error, so it does not trip
// alerting keyed on errors. It logs variable names only — BAO_TOKEN and the
// key variables hold secrets.
//
// Whether a variable is in effect follows the SDK's own reading: either the
// resulting config (verification, SRV lookup, redirects) or api.ReadBaoVariable,
// which is what the SDK calls, so an empty value and the BAO_-masks-VAULT_
// fallback behave identically here.
func logEnvironment(cfg Config, c *api.Config) {
	if tc := c.TLSConfig(); tc != nil && tc.InsecureSkipVerify {
		attrs := []any{"variable", envSpelling(api.EnvVaultSkipVerify)}
		if cfg.TLSCAFile != "" {
			attrs = append(attrs, "overrides", "openbao.tls_ca_file")
		}
		slog.Warn("OpenBao server certificate verification is OFF for the connection carrying the login and the signing token", attrs...)
	}

	for _, v := range envVariables {
		if api.ReadBaoVariable(v.name) == "" {
			continue
		}
		if v.inEffect != nil && !v.inEffect(c) {
			continue
		}
		if v.supersededBy != nil {
			if setting := v.supersededBy(cfg); setting != "" {
				slog.Info("OpenBao environment variable has no effect",
					"variable", envSpelling(v.name), "superseded_by", setting)
				continue
			}
		}
		attrs := []any{"variable", envSpelling(v.name), "effect", v.effect}
		if v.overrides != "" {
			attrs = append(attrs, "overrides", v.overrides)
		}
		slog.Warn("OpenBao client setting taken from the environment", attrs...)
	}
}

// envVariablesSetSuffix names, for an error message, every variable the SDK
// reads a non-empty value from — names only, as logEnvironment does — or
// returns "" when there are none.
func envVariablesSetSuffix() string {
	names := []string{api.EnvVaultSkipVerify}
	for _, v := range envVariables {
		names = append(names, v.name)
	}
	var set []string
	for _, n := range names {
		if api.ReadBaoVariable(n) != "" {
			set = append(set, envSpelling(n))
		}
	}
	if len(set) == 0 {
		return ""
	}
	return " (OpenBao environment variables set: " + strings.Join(set, ", ") + ")"
}

// withholdURL replaces a URL parse error with one that names variable, the
// environment variable that supplied the URL, and carries none of the URL
// itself. *url.Error quotes the whole URL, and the reason it wraps can quote
// part of it too (an invalid port, an invalid escape), so a proxy or agent
// address with a credential in it would otherwise reach the log. An empty
// variable means the URL is openvox-ca's own configuration, which keeps the
// detail.
func withholdURL(err error, variable string) error {
	var urlErr *url.Error
	if variable == "" || !errors.As(err, &urlErr) {
		return err
	}
	return fmt.Errorf("%s: %s of the URL failed (value withheld)", variable, urlErr.Op)
}

// proxyVariable returns the spelling of the proxy variable the SDK parses:
// BAO_PROXY_ADDR supersedes BAO_HTTP_PROXY when both are set.
func proxyVariable() string {
	if api.ReadBaoVariable(api.EnvVaultProxyAddr) != "" {
		return envSpelling(api.EnvVaultProxyAddr)
	}
	return envSpelling(api.EnvHTTPProxy)
}

// envSpelling returns the spelling of name the SDK actually read: the BAO_
// one whenever it is present, even empty, otherwise the VAULT_ fallback.
func envSpelling(name string) string {
	if _, ok := os.LookupEnv(name); ok {
		return name
	}
	return api.UpstreamVariableName(name)
}
