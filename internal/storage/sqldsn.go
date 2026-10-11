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
	"errors"

	"github.com/uptrace/bun/driver/pgdriver"
)

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
