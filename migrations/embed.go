// Package migrations exposes the embedded SQLite schema migrations.
package migrations

import "embed"

// FS contains ordered SQL migrations.
//
//go:embed *.sql
var FS embed.FS
