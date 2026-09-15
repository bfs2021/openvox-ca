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

package main

import (
	"bytes"
	"log/slog"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The startup decision on key-material permissions. World access is refused
// because a CA private key every local account can read is one to treat as
// exposed; group access is warned about because a Kubernetes fsGroup reapplies
// it at every mount and an arbitrary-uid platform needs it to reach a store it
// did not create.
var _ = Describe("reportKeyPermissions", func() {
	// captureWarnings installs a Warn-level handler and returns what was written,
	// the idiom this package already uses for log assertions.
	captureWarnings := func() *bytes.Buffer {
		GinkgoHelper()
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(func() { slog.SetDefault(orig) })
		return &buf
	}

	worldReadable := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db", Mode: os.FileMode(0o644)}
	groupReadable := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db", Mode: os.FileMode(0o640)}

	It("starts with nothing to report", func() {
		buf := captureWarnings()

		Expect(reportKeyPermissions(nil, false)).To(Succeed(), "no findings")
		Expect(buf.String()).To(BeEmpty(), "nothing logged")
	})

	It("refuses to start on world-accessible key material", func() {
		err := reportKeyPermissions([]storage.KeyPermWarning{worldReadable}, false)

		Expect(err).To(HaveOccurred(), "world-accessible key material")
		Expect(err.Error()).To(ContainSubstring("refusing to start"), "the refusal")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "the file at fault")
		Expect(err.Error()).To(ContainSubstring("chmod o-rwx"), "the remedy")
	})

	// Group access must not be a refusal. Under the chart's default fsGroup the
	// kubelet ORs group access back into the volume at every mount, so refusing
	// would stop the CA starting on the project's own recommended deployment.
	It("warns but starts when key material is only group-accessible", func() {
		buf := captureWarnings()

		Expect(reportKeyPermissions([]storage.KeyPermWarning{groupReadable}, false)).To(Succeed(),
			"group access must not stop the CA starting")
		Expect(buf.String()).To(ContainSubstring("readable by its group"), "the warning")
		Expect(buf.String()).To(ContainSubstring(groupReadable.Path), "the file named")
	})

	// The opt-out downgrades the refusal, and shouts. An operator who reaches for
	// it should be in no doubt what they have turned off.
	It("starts on world-accessible key material when told to, shouting about it", func() {
		buf := captureWarnings()

		Expect(reportKeyPermissions([]storage.KeyPermWarning{worldReadable}, true)).To(Succeed(),
			"the opt-out downgrades the refusal")
		Expect(buf.String()).To(ContainSubstring("INSECURE"), "the shouting")
		Expect(buf.String()).To(ContainSubstring("ROTATE IT"), "what the operator must now do")
		Expect(buf.String()).To(ContainSubstring(worldReadable.Path), "the file named")
	})

	// The opt-out is for world access only; it does not silence anything else,
	// and it does not turn a group finding into a scream.
	It("still reports group access as a group finding under the opt-out", func() {
		buf := captureWarnings()

		Expect(reportKeyPermissions([]storage.KeyPermWarning{groupReadable}, true)).To(Succeed())
		Expect(buf.String()).To(ContainSubstring("readable by its group"), "the group warning")
		Expect(buf.String()).NotTo(ContainSubstring("INSECURE"), "no scream for group access")
	})

	// Several findings, and the refusal has to fire on the world one wherever it
	// sits in the list rather than only when it happens to come first.
	It("refuses when a world-accessible file follows a group-accessible one", func() {
		_ = captureWarnings()

		err := reportKeyPermissions([]storage.KeyPermWarning{groupReadable, worldReadable}, false)

		Expect(err).To(HaveOccurred(), "the world-accessible file is not first")
		Expect(err.Error()).To(ContainSubstring("refusing to start"), "the refusal")
	})
})
