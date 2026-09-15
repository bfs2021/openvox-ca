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

// Not built on Windows: these specs set syscall.Umask, which does not exist
// there, and file modes do not carry the meaning they are about. The build
// system tolerates a Windows target but nothing ships one.
//go:build !windows

package storage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The SQLite database holds the CA private key as a blob (KeyCAKey), unencrypted
// unless the operator opts into encrypt_ca_key, so the file carries the material
// the filesystem backend keeps under private/.
//
// The invariant these specs pin is narrow and deliberate: **no world bits, ever,
// on a file openvox-ca creates**. It is not "0600". Group access is permitted
// because a Kubernetes fsGroup ORs it back into the volume at every mount and an
// arbitrary-uid platform needs it to reach a store it did not create; forcing
// 0600 would fight both and protect nothing, since the pod's own group is not a
// third party. What group access cannot be is world access, and that is what is
// asserted here.
//
// The modes are written as literals rather than as sqliteFilePermCreate. Asserting
// the constant would compare the code against itself; these assert the guarantee
// an operator is given.
//
// The sidecars matter as much as the database: a committed page lives in the WAL
// until a checkpoint moves it, so which file holds the key bytes at a given
// instant is a function of checkpoint state, not of anything the operator
// controls. -journal joins them because journal_mode=WAL is only a default and
// the DSN can override it.
const (
	umaskLoose  = 0o022 // the usual default: turns a 0666 create into 0644
	umaskLooser = 0o000 // nothing masked at all: a 0666 create stays 0666
	umaskTight  = 0o077 // group stripped as well as world
)

// permOf stats path and returns its permission bits, failing the spec if the
// file is absent. Absence is a failure rather than a skip: every caller below
// has just done the work that creates the file, so a missing file means the
// spec stopped exercising what it claims to.
func permOf(path string) os.FileMode {
	GinkgoHelper()
	info, err := os.Stat(path)
	Expect(err).NotTo(HaveOccurred(), "stat %s", path)
	return info.Mode().Perm()
}

// worldBits returns the permission bits granted to users outside the owner and
// the group, which is the only thing these specs care about.
func worldBits(path string) os.FileMode {
	GinkgoHelper()
	return permOf(path) & 0o007
}

// sqliteSidecars names the two files SQLite maintains beside the database in WAL
// mode.
func sqliteSidecars(db string) (wal, shm string) {
	return db + "-wal", db + "-shm"
}

var _ = Describe("SQLiteFilePermissions", func() {
	var dbPath string

	// A permissive umask is set for every spec in this block. Without it the
	// result would depend on the umask of whoever ran the suite, and a developer
	// or CI runner sitting at 0077 would see these pass against code that offers
	// no guarantee at all.
	BeforeEach(func() {
		old := syscall.Umask(umaskLoose)
		DeferCleanup(func() { syscall.Umask(old) })
		dbPath = filepath.Join(GinkgoT().TempDir(), "ca.db")
	})

	// openAt opens a backend on dbPath, migrates it, and writes a blob so the WAL
	// has content. Returns the backend for the caller to keep using.
	openAt := func() *SQLBackend {
		GinkgoHelper()
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
		Expect(b.Put(context.Background(), KeyCAKey, []byte("-----BEGIN RSA PRIVATE KEY-----"), BlobPrivate)).
			To(Succeed(), "Put CA key")
		return b
	}

	It("creates the database with no world access", func() {
		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(worldBits(dbPath)).To(BeZero(), "world bits on the database")
	})

	It("creates the -wal and -shm sidecars with no world access", func() {
		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		wal, shm := sqliteSidecars(dbPath)
		Expect(worldBits(wal)).To(BeZero(), "world bits on -wal")
		Expect(worldBits(shm)).To(BeZero(), "world bits on -shm")
	})

	// The spec that would have caught issue #351. An umask of 0000 masks nothing,
	// so a driver-created database lands at 0666 and every local account can read
	// the key. The mode is chosen at creation rather than inherited, so the umask
	// cannot widen it.
	It("grants no world access even when the umask masks nothing", func() {
		old := syscall.Umask(umaskLooser)
		DeferCleanup(func() { syscall.Umask(old) })

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		wal, shm := sqliteSidecars(dbPath)
		Expect(worldBits(dbPath)).To(BeZero(), "world bits on the database under umask 0000")
		Expect(worldBits(wal)).To(BeZero(), "world bits on -wal under umask 0000")
		Expect(worldBits(shm)).To(BeZero(), "world bits on -shm under umask 0000")
	})

	// The other half of the policy, and the reason this is not simply 0600: group
	// access survives. A Kubernetes fsGroup reapplies it at every mount, and on an
	// arbitrary-uid platform it is how the CA reaches a database created by a
	// previous pod under a different uid. Taking it away would break those
	// deployments to protect against the pod's own group.
	It("leaves group access in place when the umask permits it", func() {
		old := syscall.Umask(umaskLooser)
		DeferCleanup(func() { syscall.Umask(old) })

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o660)), "database mode under umask 0000")
	})

	// The umask still narrows, it just cannot widen. An operator who wants the
	// group bits gone sets a umask and gets them gone.
	It("lets a stricter umask narrow the mode further", func() {
		old := syscall.Umask(umaskTight)
		DeferCleanup(func() { syscall.Umask(old) })

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o600)), "database mode under umask 0077")
	})

	// Nothing here modifies a file that already exists. A database whose mode is
	// wrong is the operator's to fix, and the server refuses to serve it rather
	// than silently correcting it -- see StorageService.CheckKeyPermissions and
	// the startup check that acts on it.
	It("leaves an existing database's mode alone", func() {
		Expect(os.WriteFile(dbPath, nil, 0o644)).To(Succeed(), "seed a world-readable database")

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o644)), "the mode the operator left")
	})

	// "Only if it does not already exist in any form" is O_EXCL's contract, and
	// these three are the forms that would otherwise be dangerous: a directory
	// whose mode we would have replaced, a symlink we would have written through,
	// and a FIFO that would have blocked a reader for ever.
	It("does not create through, or modify, a directory at the database path", func() {
		dir := filepath.Join(GinkgoT().TempDir(), "adirectory")
		Expect(os.Mkdir(dir, 0o755)).To(Succeed(), "seed a directory where a database is named")

		_, _ = NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dir})

		Expect(permOf(dir)).To(Equal(os.FileMode(0o755)), "directory mode left alone")
	})

	// A symlink whose target does not exist yet is the operator's own
	// configuration -- "point the CA at the data volume, then bootstrap" -- so it
	// is resolved and the real file is created, with the same mode rule. O_EXCL
	// still applies at the resolved path, so an existing file there is never
	// written through or clobbered.
	It("creates the target of a dangling symlink, with no world access", func() {
		target := filepath.Join(GinkgoT().TempDir(), "elsewhere.db")
		Expect(os.Symlink(target, dbPath)).To(Succeed(), "plant a dangling symlink")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })

		Expect(target).To(BeAnExistingFile(), "the database was created at the link target")
		Expect(worldBits(target)).To(BeZero(), "world bits on the created target")
	})

	It("does not block on a FIFO at the database path", func() {
		Expect(syscall.Mkfifo(dbPath, 0o644)).To(Succeed(), "plant a FIFO")

		// Reaching this assertion at all is the point: opening a FIFO for reading
		// blocks until a writer appears, so a create that did not use O_EXCL, or
		// any inspection that opened the path, would hang here for ever and take
		// the suite with it rather than failing.
		_, _ = NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o644)), "FIFO mode left alone")
	})

	// A symlinked database is the operator's own choice, and it worked before any
	// of this existed. The DSN is resolved so the sidecars and the lock directory
	// are derived from the same real path -- which is also where SQLite puts them,
	// since it canonicalises the filename first.
	It("accepts a DSN that is a symlink to an existing database", func() {
		realDir := GinkgoT().TempDir()
		realDB := filepath.Join(realDir, "real.db")
		link := filepath.Join(GinkgoT().TempDir(), "link.db")
		Expect(os.WriteFile(realDB, nil, 0o600)).To(Succeed(), "seed the relocated database")
		Expect(os.Symlink(realDB, link)).To(Succeed(), "point the DSN at a symlink")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + link})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
		Expect(b.Put(context.Background(), KeyCAKey, []byte("key"), BlobPrivate)).To(Succeed(), "Put CA key")

		wal, shm := sqliteSidecars(realDB)
		Expect(worldBits(realDB)).To(BeZero(), "world bits on the resolved database")
		Expect(worldBits(wal)).To(BeZero(), "world bits on -wal beside the resolved path")
		Expect(worldBits(shm)).To(BeZero(), "world bits on -shm beside the resolved path")
	})

	// Everything derived from the DSN has to come from the same resolved path. The
	// lock directory is what stops a second process opening the store, so if it
	// were derived from the spelling instead, two processes reaching one database
	// by two names would take two different locks and exclude nobody.
	It("puts the lock directory beside the resolved database, not beside the link", func() {
		realDB := filepath.Join(GinkgoT().TempDir(), "real.db")
		link := filepath.Join(GinkgoT().TempDir(), "link.db")
		Expect(os.WriteFile(realDB, nil, 0o600)).To(Succeed(), "seed the database")
		Expect(os.Symlink(realDB, link)).To(Succeed(), "reach it through a link as well")

		viaLink, ok := sqliteLockDir("file:" + link)
		Expect(ok).To(BeTrue(), "lock directory for the link spelling")
		viaTarget, ok := sqliteLockDir("file:" + realDB)
		Expect(ok).To(BeTrue(), "lock directory for the target spelling")

		Expect(viaLink).To(Equal(viaTarget), "both spellings must lock in the same place")
	})

	// The driver decodes %HH in a file: URI, so this has to read the DSN the same
	// way or it protects a filename nobody opens. Before the decode was added this
	// created an empty "ca%20b.db" at the encoded spelling while the database that
	// actually held the key was created beside it, by the driver, at the umask.
	It("creates the file the driver opens when the DSN is percent-encoded", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Chdir(dir)

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:ca%20b.db"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(filepath.Join(dir, "ca b.db")).To(BeAnExistingFile(), "the decoded name is the real database")
		Expect(worldBits(filepath.Join(dir, "ca b.db"))).To(BeZero(), "world bits on the decoded database")
		Expect(filepath.Join(dir, "ca%20b.db")).NotTo(BeAnExistingFile(), "no decoy at the encoded name")
	})

	// A DSN with a malformed escape is one this cannot read, and the parser reports
	// that the same way it reports an in-memory database: no file. Taken at face
	// value it would skip creation entirely and let the driver make the database at
	// the umask, which is issue #351 again by way of giving up.
	It("refuses a DSN whose escapes it cannot read", func() {
		_, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:/var/lib/ca%zz.db"})
		Expect(err).To(MatchError(ContainSubstring("sqlite dsn")), "NewSQLBackend error")
	})

	// An in-memory database has no file, and the open path must not invent one
	// named after the DSN. The spec runs from its own temp directory so that the
	// regression it guards against would create that file inside the sandbox
	// rather than in the checked-out source tree.
	It("creates no file for an in-memory database", func() {
		GinkgoT().Chdir(GinkgoT().TempDir())

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(":memory:").NotTo(BeAnExistingFile(), "a file named for the DSN")
	})
})
