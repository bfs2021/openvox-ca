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
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun/driver/pgdriver"
)

// resolveSQLDSN returns the DSN spec describes, reading it from DSNFile when
// that is the one set. Exactly one of DSN and DSNFile must be set: both is
// refused rather than ranked, because whichever lost would be a credential the
// operator believes is in use and is not.
//
// No error here names the DSN or any part of the file's contents; only the
// path.
func resolveSQLDSN(spec SQLSpec) (string, error) {
	switch {
	case spec.DSN != "" && spec.DSNFile != "":
		return "", errors.New("sql_dsn and sql_dsn_file are mutually exclusive; set one")
	case spec.DSNFile != "":
		dsn, err := readDSNFile(spec.DSNFile)
		if err != nil {
			return "", fmt.Errorf("reading sql_dsn_file: %w", err)
		}
		return dsn, nil
	case spec.DSN != "":
		return spec.DSN, nil
	default:
		return "", errors.New("sql backend requires sql_dsn or sql_dsn_file")
	}
}

// readDSNFile returns the first line of path with surrounding whitespace
// trimmed, as the OpenBao credential files are read, so a trailing newline
// from `echo` or a Kubernetes Secret does not become part of the DSN. (The CA
// key passphrase file also takes only the first line, but does not trim
// spaces.)
func readDSNFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		return "", fmt.Errorf("%s is empty", path)
	}
	line := strings.TrimSpace(sc.Text())
	if line == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return line, nil
}

// DSNHasPassword reports whether dsn carries a non-empty database password.
// It exists so the server can warn when a password has been put somewhere
// every local user can read, such as the command line, which is exposed
// whichever backend the DSN is for -- so the backend is not an input.
//
// A postgres://, postgresql:// or unix:// URL with userinfo is read the way
// pgdriver reads it, taking the password from the userinfo alone; anything
// else is read as a go-sql-driver/mysql DSN. Both are needed: MySQL's parser
// rejects a PostgreSQL URL outright, and url.Parse finds no userinfo in a MySQL
// DSN. Userinfo is what decides, not the scheme alone, because url.Parse also
// accepts "postgres:secret@tcp(db)/ca" -- a MySQL DSN for a user called
// postgres -- as an opaque URL with that scheme. A DSN neither parser accepts,
// which includes every SQLite path, is reported as having none.
func DSNHasPassword(dsn string) bool {
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		switch u.Scheme {
		case "postgres", "postgresql", "unix":
			pw, _ := u.User.Password()
			return pw != ""
		}
	}
	cfg, err := mysqldriver.ParseDSN(dsn)
	return err == nil && cfg.Passwd != ""
}

// errPostgresDSNMalformed stands in for pgdriver's own parse error, which is
// withheld because it can repeat the DSN, password included.
var errPostgresDSNMalformed = errors.New("parsing postgres dsn: the DSN is malformed " +
	"(the parser's message is withheld because it can repeat the DSN, password included); " +
	"check its scheme (postgres://, postgresql:// or unix://), host, port and query parameters")

// newPostgresConnector builds a pgdriver connector from opts, turning a panic
// into errPostgresDSNMalformed.
//
// pgdriver.WithDSN panics rather than returning an error when it cannot parse
// the DSN, and the panic value is the parser's error -- for a url.Parse
// failure, a *url.Error that quotes the whole DSN. Left alone, that panic
// prints the database password to stderr, which is the journal under systemd
// and the pod log under Kubernetes. None of the panic value is kept, because
// there is no reliable way to tell which of pgdriver's messages repeat the DSN.
func newPostgresConnector(opts ...pgdriver.Option) (connector *pgdriver.Connector, err error) {
	defer func() {
		if recover() != nil {
			connector, err = nil, errPostgresDSNMalformed
		}
	}()
	return pgdriver.NewConnector(opts...), nil
}
