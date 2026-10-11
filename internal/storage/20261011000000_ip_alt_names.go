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

	"github.com/uptrace/bun"
)

// Migration 20261011000000 (ip_alt_names): add the certificate index's IP SAN
// column, so the indexed certificate_statuses path can list IP SANs in
// subject_alt_names as the per-certificate path does.
//
// Existing rows get NULL, which beside a populated fingerprint reads as a
// projection written before the column existed: the row decoder reports it as
// no projection at all, readers fall back to the stored PEM, and the CA's
// index repair pass rewrites it from that PEM at startup. So this migration
// needs no data backfill of its own, just as the certindex migration did not.
func init() {
	sqlMigrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			return addColumnIfMissing(ctx, idb, inventoryTableV1, "ip_alt_names", "TEXT")
		})
	}, func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			return dropColumnIfPresent(ctx, idb, inventoryTableV1, "ip_alt_names")
		})
	})
}
