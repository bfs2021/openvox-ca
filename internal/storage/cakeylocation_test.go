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

package storage_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The filesystem backend keeps the CA key where OpenVox Server does, at the top
// of the cadir, so a cadir handed back to OpenVox Server has it where it looks.
// A cadir that has it only in private/, where this backend kept it before, is
// read and written there; neither layout is rearranged by starting on it.
var _ = Describe("Filesystem CA key location", func() {
	var (
		ctx    = context.Background()
		dir    string
		store  *storage.StorageService
		top    string
		legacy string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		store = storage.New(dir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		top = filepath.Join(dir, "ca_key.pem")
		legacy = filepath.Join(dir, "private", "ca_key.pem")
	})

	It("writes a new key at the top of the cadir, private to the owner", func() {
		Expect(store.SaveCAKey(ctx, []byte("key"))).To(Succeed())

		info, err := os.Stat(top)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		Expect(legacy).NotTo(BeAnExistingFile())
	})

	It("reads the key OpenVox Server left at the top of the cadir", func() {
		Expect(os.WriteFile(top, []byte("ovs-key"), 0o640)).To(Succeed())

		Expect(store.GetCAKey(ctx)).To(Equal([]byte("ovs-key")))
		Expect(store.HasCAKey(ctx)).To(BeTrue())
	})

	It("leaves the mode of a key it did not create alone", func() {
		// OpenVox Server creates its key group-readable. Reading it is not
		// licence to chmod it.
		Expect(os.WriteFile(top, []byte("ovs-key"), 0o640)).To(Succeed())
		Expect(os.Chmod(top, 0o640)).To(Succeed())
		_, err := store.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Stat(top)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o640)))
	})

	Context("when the cadir keeps the key only in private/", func() {
		BeforeEach(func() {
			Expect(os.WriteFile(legacy, []byte("old-key"), 0o600)).To(Succeed())
		})

		It("reads it there", func() {
			Expect(store.GetCAKey(ctx)).To(Equal([]byte("old-key")))
			Expect(store.HasCAKey(ctx)).To(BeTrue())
		})

		It("writes it there, rather than creating a second key beside it", func() {
			// A write to the top of the cadir would leave two different keys,
			// which every later read refuses.
			Expect(store.SaveCAKey(ctx, []byte("new-key"))).To(Succeed())
			Expect(os.ReadFile(legacy)).To(Equal([]byte("new-key")))
			Expect(top).NotTo(BeAnExistingFile())
		})
	})

	Context("when both locations hold the same key", func() {
		BeforeEach(func() {
			Expect(os.WriteFile(top, []byte("same-key"), 0o600)).To(Succeed())
			Expect(os.WriteFile(legacy, []byte("same-key"), 0o600)).To(Succeed())
		})

		It("reads it", func() {
			Expect(store.GetCAKey(ctx)).To(Equal([]byte("same-key")))
		})

		It("removes both copies when the key is deleted", func() {
			// Left behind, the second copy would be found and used.
			Expect(store.Backend().Delete(ctx, storage.KeyCAKey)).To(Succeed())
			Expect(top).NotTo(BeAnExistingFile())
			Expect(legacy).NotTo(BeAnExistingFile())
			_, err := store.GetCAKey(ctx)
			Expect(err).To(MatchError(fs.ErrNotExist))
		})
	})

	Context("when the two locations hold different keys", func() {
		BeforeEach(func() {
			Expect(os.WriteFile(top, []byte("one-key"), 0o600)).To(Succeed())
			Expect(os.WriteFile(legacy, []byte("another-key"), 0o600)).To(Succeed())
		})

		It("refuses to read either", func() {
			_, err := store.GetCAKey(ctx)
			Expect(err).To(MatchError(storage.ErrCAKeyConflict))
			Expect(err).To(MatchError(ContainSubstring(top)), "the error must name both files")
			Expect(err).To(MatchError(ContainSubstring(legacy)), "the error must name both files")
		})

		It("refuses to say whether a key exists", func() {
			_, err := store.HasCAKey(ctx)
			Expect(err).To(MatchError(storage.ErrCAKeyConflict))
		})

		It("refuses to overwrite either, and changes neither", func() {
			Expect(store.SaveCAKey(ctx, []byte("third-key"))).To(MatchError(storage.ErrCAKeyConflict))
			Expect(os.ReadFile(top)).To(Equal([]byte("one-key")))
			Expect(os.ReadFile(legacy)).To(Equal([]byte("another-key")))
		})

		It("refuses to delete either", func() {
			Expect(store.Backend().Delete(ctx, storage.KeyCAKey)).To(MatchError(storage.ErrCAKeyConflict))
			Expect(top).To(BeAnExistingFile())
			Expect(legacy).To(BeAnExistingFile())
		})
	})

	Describe("CheckKeyPermissions", func() {
		It("reports a top-level CA key readable beyond its owner", func() {
			Expect(os.WriteFile(top, []byte("key"), 0o644)).To(Succeed())
			Expect(os.Chmod(top, 0o644)).To(Succeed())

			Expect(store.CheckKeyPermissions()).To(ConsistOf(
				storage.KeyPermWarning{Path: top, Mode: 0o644}))
		})

		It("reports a key kept in private/ once, not twice", func() {
			Expect(os.WriteFile(legacy, []byte("key"), 0o644)).To(Succeed())
			Expect(os.Chmod(legacy, 0o644)).To(Succeed())

			Expect(store.CheckKeyPermissions()).To(ConsistOf(
				storage.KeyPermWarning{Path: legacy, Mode: 0o644}))
		})
	})
})
