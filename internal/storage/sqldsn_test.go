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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// secret is the password every fixture DSN below carries, so a spec can assert
// that no error or message repeats it.
const secret = "SUPERSECRET"

var _ = Describe("openSQLDB for PostgreSQL", func() {
	It("refuses a malformed DSN with an error that does not repeat it", func() {
		// pgdriver.WithDSN panics on a DSN url.Parse rejects, and the panic
		// value quotes the whole DSN. The invalid port is what makes it fail.
		var (
			db  any
			err error
		)
		Expect(func() {
			db, _, err = openSQLDB(SQLConfig{Dialect: SQLPostgres, DSN: "postgres://ca:" + secret + "@db:54 32/ca"})
		}).NotTo(Panic())
		Expect(err).To(MatchError(errPostgresDSNMalformed))
		Expect(err.Error()).NotTo(ContainSubstring(secret))
		Expect(db).To(BeNil())
	})

	It("refuses a DSN pgdriver rejects by message rather than by url.Parse", func() {
		// "unix socket DSN requires a path: <dsn>" is the other pgdriver
		// message that repeats the DSN.
		_, _, err := openSQLDB(SQLConfig{Dialect: SQLPostgres, DSN: "unix://ca:" + secret + "@ca"})
		Expect(err).To(MatchError(errPostgresDSNMalformed))
		Expect(err.Error()).NotTo(ContainSubstring(secret))
	})

	It("opens a well-formed DSN without dialling it", func() {
		// sql.OpenDB is lazy, so this needs no server: it pins that the
		// recover wrapper passes a good connector through.
		db, _, err := openSQLDB(SQLConfig{Dialect: SQLPostgres, DSN: "postgres://ca:" + secret + "@127.0.0.1:1/ca"})
		Expect(err).NotTo(HaveOccurred())
		Expect(db).NotTo(BeNil())
		Expect(db.Close()).To(Succeed())
	})
})
