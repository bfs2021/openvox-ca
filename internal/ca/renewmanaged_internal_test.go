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

// White-box, because reconcileManagedCert is how a managed certificate is
// renewed and it is unexported; memStore comes from managedcert_reconcile_test.go.
package ca

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// Agent renewal recreates the certificate it renews (reissueLeafLocked). A
// managed certificate must not be renewed that way: its names come from
// configuration, and a name removed there has to disappear at the next renewal
// rather than be carried forward from the predecessor for ever. The two share
// issueLeafLocked and nothing above it, and this pins which side managed
// renewal is on.
var _ = Describe("Renewing a managed certificate", func() {
	const subject = "managed.test"

	var (
		ctx   context.Context
		myCA  *CA
		fake  *memStore
		entry ManagedCert
	)

	BeforeEach(func() {
		ctx = context.Background()
		myCA = New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		fake = &memStore{}
		entry = ManagedCert{
			Spec: CertSpec{
				Subject:     subject,
				DNSNames:    []string{subject, "retired.example.com"},
				TTL:         90 * 24 * time.Hour,
				RenewBefore: 30 * 24 * time.Hour,
			},
			Load: fake.load,
			Save: fake.save,
		}
	})

	It("takes its names from configuration, not from the certificate it replaces", func() {
		issued, err := myCA.reconcileManagedCert(ctx, entry, time.Now().UTC())
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue())
		Expect(fake.stored().DNSNames).To(ConsistOf(subject, "retired.example.com"))

		// A certificate carrying names beyond its spec is still current, so
		// dropping one from configuration does not reissue on its own. The
		// renewal that follows is the time-driven one, which is the renewal
		// that could carry the predecessor's names forward.
		entry.Spec.DNSNames = []string{subject}
		issued, err = myCA.reconcileManagedCert(ctx, entry, time.Now().UTC())
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeFalse(), "this spec drives a time-driven renewal, not a spec-driven reissue")

		// Inside the 30-day renew window of a 90-day certificate, and not expired.
		issued, err = myCA.reconcileManagedCert(ctx, entry, time.Now().UTC().Add(80*24*time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue())
		Expect(fake.stored().DNSNames).To(ConsistOf(subject),
			"a managed renewal must issue the configured names, not the predecessor's")
	})
})
