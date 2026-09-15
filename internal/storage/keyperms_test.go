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

//go:build !windows

package storage

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// CheckKeyPermissions is the whole of the control now: nothing corrects a mode,
// so what this reports is what the server acts on. The distinction it has to draw
// is world versus group -- world means every local account can read the CA private
// key and is refused at startup, group is what a Kubernetes fsGroup reapplies at
// every mount and is only warned about.
var _ = Describe("CheckKeyPermissions", func() {
	// findFor returns the warning for path, or nil. Specs assert on the classified
	// finding rather than on list positions, which reorder as sources are added.
	findFor := func(warnings []KeyPermWarning, path string) *KeyPermWarning {
		for i := range warnings {
			if warnings[i].Path == path {
				return &warnings[i]
			}
		}
		return nil
	}

	Describe("the local private-key directory", func() {
		var dir, keyPath string

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
			Expect(os.MkdirAll(filepath.Join(dir, "private"), DirPerm)).To(Succeed())
			keyPath = filepath.Join(dir, "private", "ca_key.pem")
		})

		serviceOn := func() *StorageService {
			GinkgoHelper()
			return NewWithBackend(NewFilesystemBackend(dir), filepath.Join(dir, "private"))
		}

		It("says nothing about a key at 0600", func() {
			Expect(os.WriteFile(keyPath, nil, 0o600)).To(Succeed())
			Expect(serviceOn().CheckKeyPermissions()).To(BeEmpty(), "warnings for a correct key")
		})

		It("reports a group-readable key as not world-accessible", func() {
			Expect(os.WriteFile(keyPath, nil, 0o640)).To(Succeed())

			w := findFor(serviceOn().CheckKeyPermissions(), keyPath)
			Expect(w).NotTo(BeNil(), "warning for a group-readable key")
			Expect(w.WorldAccessible()).To(BeFalse(), "group access is not world access")
		})

		It("reports a world-readable key as world-accessible", func() {
			Expect(os.WriteFile(keyPath, nil, 0o644)).To(Succeed())

			w := findFor(serviceOn().CheckKeyPermissions(), keyPath)
			Expect(w).NotTo(BeNil(), "warning for a world-readable key")
			Expect(w.WorldAccessible()).To(BeTrue(), "world access")
		})

		// World execute grants no read, but on a key file it is still access
		// granted to everyone and there is no legitimate reason for it.
		It("counts world-execute as world access", func() {
			Expect(os.WriteFile(keyPath, nil, 0o601)).To(Succeed())

			w := findFor(serviceOn().CheckKeyPermissions(), keyPath)
			Expect(w).NotTo(BeNil(), "warning for a world-executable key")
			Expect(w.WorldAccessible()).To(BeTrue(), "world execute is world access")
		})
	})

	Describe("a backend that declares its own key files", func() {
		var dbPath string
		var svc *StorageService

		BeforeEach(func() {
			dbPath = filepath.Join(GinkgoT().TempDir(), "ca.db")
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
			Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
			DeferCleanup(func() { _ = b.Close() })
			Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
			Expect(b.Put(context.Background(), KeyCAKey, []byte("key"), BlobPrivate)).To(Succeed(), "Put CA key")

			// The backend reports the resolved path, since everything derived from
			// the DSN comes from one resolution. On a host where the temp directory
			// is reached through a symlink -- /var on a Mac -- that is not the
			// spelling this spec started with, so line the two up rather than
			// comparing a real path against a link.
			resolved, err := filepath.EvalSymlinks(dbPath)
			Expect(err).NotTo(HaveOccurred(), "resolving the database path")
			dbPath = resolved

			// No local private-key directory: the database is the only source, so a
			// finding here can only have come through KeyFileLister.
			svc = NewWithBackend(b, "")
		})

		// A group-accessible database is reported, but as a group finding: the
		// caller warns about those and refuses only on world. Asserted as "nothing
		// world-accessible" rather than "no findings", because the group finding is
		// the expected steady state under a Kubernetes fsGroup.
		It("reports no world access when the database is only group-accessible", func() {
			Expect(os.Chmod(dbPath, 0o660)).To(Succeed())

			for _, w := range svc.CheckKeyPermissions() {
				Expect(w.WorldAccessible()).To(BeFalse(), "world access on %s (mode %s)", w.Path, w.Mode)
			}
		})

		It("reports a world-readable database", func() {
			Expect(os.Chmod(dbPath, 0o644)).To(Succeed())

			w := findFor(svc.CheckKeyPermissions(), dbPath)
			Expect(w).NotTo(BeNil(), "warning for the database")
			Expect(w.WorldAccessible()).To(BeTrue(), "world access")
		})

		// The WAL holds committed pages, which is to say it can hold the key, and
		// which of the files has it at a given instant is a matter of checkpoint
		// timing rather than anything the operator controls.
		It("reports a world-readable -wal sidecar", func() {
			wal := dbPath + "-wal"
			Expect(wal).To(BeAnExistingFile(), "the WAL exists while the backend is open")
			Expect(os.Chmod(wal, 0o644)).To(Succeed())

			w := findFor(svc.CheckKeyPermissions(), wal)
			Expect(w).NotTo(BeNil(), "warning for the -wal sidecar")
			Expect(w.WorldAccessible()).To(BeTrue(), "world access")
		})
	})

	// An in-memory database has no files, and a backend that declares none must
	// not produce phantom findings for paths that do not exist.
	It("reports nothing for a backend with no files", func() {
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(NewWithBackend(b, "").CheckKeyPermissions()).To(BeEmpty(), "warnings for an in-memory store")
	})
})
