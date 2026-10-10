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
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// subjectBlobLifecycle drives one subject's CSR and certificate through the
// states SaveRequest's duplicate check tells apart, asserting CSRExists and
// CertExists at each step. The check is only as good as these answers on the
// backend in use, and clean only re-opens a subject if both deletes land, so
// it is shared between the unit suite and every backend's integration suite.
func subjectBlobLifecycle(b Backend) {
	GinkgoHelper()
	ctx := context.Background()
	svc := NewWithBackend(b, "")
	const subject = "dup-node"

	expectHeld := func(csr, cert bool, when string) {
		GinkgoHelper()
		gotCSR, err := svc.CSRExists(ctx, subject)
		Expect(err).NotTo(HaveOccurred(), "CSRExists %s", when)
		Expect(gotCSR).To(Equal(csr), "CSRExists %s", when)
		gotCert, err := svc.CertExists(ctx, subject)
		Expect(err).NotTo(HaveOccurred(), "CertExists %s", when)
		Expect(gotCert).To(Equal(cert), "CertExists %s", when)
	}

	expectHeld(false, false, "before anything is stored")

	Expect(svc.SaveCSR(ctx, subject, []byte("csr-1"))).To(Succeed())
	expectHeld(true, false, "with a pending CSR")

	// What allow_duplicate_certs relies on: a second save replaces the first.
	Expect(svc.SaveCSR(ctx, subject, []byte("csr-2"))).To(Succeed())
	got, err := svc.GetCSR(ctx, subject)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(got)).To(Equal("csr-2"))

	Expect(svc.SaveCert(ctx, subject, []byte("cert"))).To(Succeed())
	expectHeld(true, true, "with a CSR and a certificate")

	// Clean deletes both, and the subject must read as empty afterwards.
	Expect(svc.DeleteCSR(ctx, subject)).To(Succeed())
	expectHeld(false, true, "after the CSR is deleted")
	Expect(svc.DeleteCert(ctx, subject)).To(Succeed())
	expectHeld(false, false, "after both are deleted")
}

// existsFailBackend fails every Exists call, standing in for a backend that is
// reachable but cannot answer.
type existsFailBackend struct {
	Backend
	err error
}

func (b existsFailBackend) Exists(context.Context, string) (bool, error) { return false, b.err }

var _ = Describe("CSRExists and CertExists", func() {
	DescribeTable("track a subject's CSR and certificate",
		func(newBackend func() Backend) { subjectBlobLifecycle(newBackend()) },
		Entry("on the filesystem backend", func() Backend {
			b := NewFilesystemBackend(GinkgoT().TempDir())
			Expect(b.EnsureReady(context.Background())).To(Succeed())
			return b
		}),
		Entry("on the SQLite backend", func() Backend { return newSQLiteBackend() }),
		Entry("on the Redis backend (miniredis)", func() Backend {
			_, cli, stop := newMiniredis()
			DeferCleanup(stop)
			return newRedisBackend(cli, "subject-blobs")
		}),
	)

	// HasCSR and HasCert read a backend error as absence. These two exist so
	// that a caller whose refusal depends on the answer gets the error instead.
	It("return the backend's error rather than reading it as absence", func() {
		fault := errors.New("backend unavailable")
		svc := NewWithBackend(existsFailBackend{Backend: NewFilesystemBackend(GinkgoT().TempDir()), err: fault}, "")

		_, err := svc.CSRExists(context.Background(), "dup-node")
		Expect(err).To(MatchError(fault))
		_, err = svc.CertExists(context.Background(), "dup-node")
		Expect(err).To(MatchError(fault))
	})
})
