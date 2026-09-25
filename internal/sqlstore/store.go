package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type PolicyItem struct {
	Prefix    string     `json:"prefix"`
	List      string     `json:"list"`
	Source    string     `json:"source"`
	FeedID    string     `json:"feed_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type FeedSource struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	List          string    `json:"list"`
	URL           string    `json:"url"`
	Interval      int       `json:"interval"` // seconds
	Enabled       bool      `json:"enabled"`
	LastSync      string    `json:"last_sync,omitempty"`
	PrefixCount   int       `json:"prefix_count"`
	LastError     string    `json:"last_error,omitempty"`
	ExpandSubnets bool      `json:"expand_subnets"`
}

type AuditEvent struct {
	Time      time.Time    `json:"time"`
	Operation string       `json:"operation"`
	List      string       `json:"list"`
	Prefix    netip.Prefix `json:"prefix"`
}

type SQLStore struct {
	db     *sql.DB
	driver string
	mu     sync.RWMutex
}

// Open initializes the SQL database with the appropriate driver and schema.
// Supported drivers: "sqlite", "postgres", "mysql".
func Open(driver, dsn string) (*SQLStore, error) {
	normalizedDriver := strings.ToLower(strings.TrimSpace(driver))
	if normalizedDriver == "sqlite3" || normalizedDriver == "" {
		normalizedDriver = "sqlite"
	}
	if normalizedDriver == "postgresql" {
		normalizedDriver = "postgres"
	}
	if normalizedDriver == "mariadb" {
		normalizedDriver = "mysql"
	}

	if normalizedDriver == "sqlite" {
		// Clean file path or in-memory
		if dsn != ":memory:" && !strings.HasPrefix(dsn, "file:") {
			dir := filepath.Dir(dsn)
			if dir != "" && dir != "." {
				_ = os.MkdirAll(dir, 0755)
			}
		}
	}

	db, err := sql.Open(normalizedDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: open %s: %w", normalizedDriver, err)
	}

	if normalizedDriver == "sqlite" {
		// Optimize SQLite for concurrent reading & fast bulk transactions
		db.SetMaxOpenConns(1) // modernc.org/sqlite recommendation for single-file writes
		if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=10000; PRAGMA synchronous=NORMAL;"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlstore: pragma setup: %w", err)
		}
	} else {
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
	}

	s := &SQLStore{
		db:     db,
		driver: normalizedDriver,
	}

	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlstore: init schema: %w", err)
	}

	return s, nil
}

func (s *SQLStore) Close() error {
	return s.db.Close()
}

func (s *SQLStore) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS feeds (
			id VARCHAR(64) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			list VARCHAR(32) NOT NULL,
			url TEXT NOT NULL,
			interval_sec INTEGER NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			last_sync VARCHAR(64),
			prefix_count INTEGER DEFAULT 0,
			last_error TEXT,
			expand_subnets INTEGER DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS policies (
			prefix VARCHAR(64) NOT NULL,
			list VARCHAR(32) NOT NULL,
			source VARCHAR(255) DEFAULT 'Manual',
			feed_id VARCHAR(64),
			expires_at VARCHAR(64),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (prefix, list)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_policies_list ON policies(list);`,
		`CREATE INDEX IF NOT EXISTS idx_policies_feed ON policies(feed_id);`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			timestamp_ms BIGINT NOT NULL,
			operation VARCHAR(32) NOT NULL,
			list VARCHAR(32) NOT NULL,
			prefix VARCHAR(64) NOT NULL
		);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) ListFeeds(ctx context.Context) ([]FeedSource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, list, url, interval_sec, enabled, last_sync, prefix_count, last_error, expand_subnets FROM feeds ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feeds []FeedSource
	for rows.Next() {
		var f FeedSource
		var enabled, expand int
		var lastSync, lastError sql.NullString
		if err := rows.Scan(&f.ID, &f.Name, &f.List, &f.URL, &f.Interval, &enabled, &lastSync, &f.PrefixCount, &lastError, &expand); err != nil {
			return nil, err
		}
		f.Enabled = enabled != 0
		f.ExpandSubnets = expand != 0
		if lastSync.Valid {
			f.LastSync = lastSync.String
		}
		if lastError.Valid {
			f.LastError = lastError.String
		}
		feeds = append(feeds, f)
	}
	return feeds, rows.Err()
}

func (s *SQLStore) SaveFeed(ctx context.Context, f FeedSource) error {
	enabled := 0
	if f.Enabled {
		enabled = 1
	}
	expand := 0
	if f.ExpandSubnets {
		expand = 1
	}

	query := `INSERT INTO feeds (id, name, list, url, interval_sec, enabled, last_sync, prefix_count, last_error, expand_subnets)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			list = excluded.list,
			url = excluded.url,
			interval_sec = excluded.interval_sec,
			enabled = excluded.enabled,
			expand_subnets = excluded.expand_subnets`

	if s.driver == "mysql" {
		query = `INSERT INTO feeds (id, name, list, url, interval_sec, enabled, last_sync, prefix_count, last_error, expand_subnets)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				name = VALUES(name),
				list = VALUES(list),
				url = VALUES(url),
				interval_sec = VALUES(interval_sec),
				enabled = VALUES(enabled),
				expand_subnets = VALUES(expand_subnets)`
	}

	_, err := s.db.ExecContext(ctx, query,
		f.ID, f.Name, f.List, f.URL, f.Interval, enabled, f.LastSync, f.PrefixCount, f.LastError, expand,
	)
	return err
}

func (s *SQLStore) UpdateFeedStatus(ctx context.Context, id string, prefixCount int, lastSync string, lastError string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE feeds SET prefix_count = ?, last_sync = ?, last_error = ? WHERE id = ?`, prefixCount, lastSync, lastError, id)
	return err
}

func (s *SQLStore) DeleteFeed(ctx context.Context, id string) ([]string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	var list string
	err = tx.QueryRowContext(ctx, `SELECT list FROM feeds WHERE id = ?`, id).Scan(&list)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}

	rows, err := tx.QueryContext(ctx, `SELECT prefix FROM policies WHERE feed_id = ?`, id)
	if err != nil {
		return nil, "", err
	}
	var deletedPrefixes []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			deletedPrefixes = append(deletedPrefixes, p)
		}
	}
	rows.Close()

	if _, err := tx.ExecContext(ctx, `DELETE FROM policies WHERE feed_id = ?`, id); err != nil {
		return nil, "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds WHERE id = ?`, id); err != nil {
		return nil, "", err
	}

	if err := tx.Commit(); err != nil {
		return nil, "", err
	}

	return deletedPrefixes, list, nil
}

func (s *SQLStore) SyncFeedPolicies(ctx context.Context, feedID, feedName, list string, newPrefixes []string) (toAdd []string, toRemove []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	// 1. Fetch current prefixes for this feed
	rows, err := tx.QueryContext(ctx, `SELECT prefix FROM policies WHERE feed_id = ?`, feedID)
	if err != nil {
		return nil, nil, err
	}
	currentMap := make(map[string]bool)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			currentMap[p] = true
		}
	}
	rows.Close()

	newMap := make(map[string]bool, len(newPrefixes))
	for _, p := range newPrefixes {
		newMap[p] = true
		if !currentMap[p] {
			toAdd = append(toAdd, p)
		}
	}

	for p := range currentMap {
		if !newMap[p] {
			toRemove = append(toRemove, p)
		}
	}

	// 2. Remove obsolete prefixes in batches
	if len(toRemove) > 0 {
		const deleteBatchSize = 500
		for i := 0; i < len(toRemove); i += deleteBatchSize {
			end := i + deleteBatchSize
			if end > len(toRemove) {
				end = len(toRemove)
			}
			chunk := toRemove[i:end]
			var qb strings.Builder
			qb.WriteString("DELETE FROM policies WHERE feed_id = ? AND prefix IN (")
			args := make([]any, 0, len(chunk)+1)
			args = append(args, feedID)
			for j, p := range chunk {
				if j > 0 {
					qb.WriteString(",")
				}
				qb.WriteString("?")
				args = append(args, p)
			}
			qb.WriteString(")")
			if _, err := tx.ExecContext(ctx, qb.String(), args...); err != nil {
				return nil, nil, err
			}
		}
	}

	// 3. Insert new prefixes in bulk chunks (500 per chunk for lightning-fast ingest)
	if len(toAdd) > 0 {
		const insertBatchSize = 500
		for i := 0; i < len(toAdd); i += insertBatchSize {
			end := i + insertBatchSize
			if end > len(toAdd) {
				end = len(toAdd)
			}
			chunk := toAdd[i:end]
			var qb strings.Builder
			qb.WriteString("INSERT INTO policies (prefix, list, source, feed_id) VALUES ")
			args := make([]any, 0, len(chunk)*4)
			for j, p := range chunk {
				if j > 0 {
					qb.WriteString(",")
				}
				qb.WriteString("(?, ?, ?, ?)")
				args = append(args, p, list, feedName, feedID)
			}
			if s.driver == "mysql" {
				qb.WriteString(" ON DUPLICATE KEY UPDATE source = VALUES(source), feed_id = VALUES(feed_id)")
			} else {
				qb.WriteString(" ON CONFLICT(prefix, list) DO UPDATE SET source = excluded.source, feed_id = excluded.feed_id")
			}
			if _, err := tx.ExecContext(ctx, qb.String(), args...); err != nil {
				return nil, nil, err
			}
		}
	}

	// 4. Update feed metadata
	nowStr := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	if _, err := tx.ExecContext(ctx, `UPDATE feeds SET prefix_count = ?, last_sync = ?, last_error = '' WHERE id = ?`, len(newPrefixes), nowStr, feedID); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}

	return toAdd, toRemove, nil
}

func (s *SQLStore) ListPoliciesPaginated(ctx context.Context, list string, search string, page, limit int) ([]PolicyItem, int, error) {
	if limit <= 0 {
		limit = 25
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	var total int
	var countQuery string
	var selectQuery string
	var args []any

	search = strings.TrimSpace(search)
	if search != "" {
		filter := "%" + search + "%"
		countQuery = `SELECT COUNT(*) FROM policies WHERE list = ? AND (prefix LIKE ? OR source LIKE ?)`
		selectQuery = `SELECT prefix, list, source, feed_id, expires_at, created_at FROM policies WHERE list = ? AND (prefix LIKE ? OR source LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []any{list, filter, filter}
	} else {
		countQuery = `SELECT COUNT(*) FROM policies WHERE list = ?`
		selectQuery = `SELECT prefix, list, source, feed_id, expires_at, created_at FROM policies WHERE list = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []any{list}
	}

	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	selectArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]PolicyItem, 0)
	for rows.Next() {
		var it PolicyItem
		var feedID, expiresAt sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&it.Prefix, &it.List, &it.Source, &feedID, &expiresAt, &createdAt); err != nil {
			return nil, 0, err
		}
		it.FeedID = feedID.String
		it.CreatedAt = createdAt
		if expiresAt.Valid {
			if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
				it.ExpiresAt = &t
			}
		}
		items = append(items, it)
	}

	return items, total, rows.Err()
}

func (s *SQLStore) AddPolicy(ctx context.Context, prefix, list, source, feedID string, expiresAt *time.Time) error {
	var expStr sql.NullString
	if expiresAt != nil {
		expStr = sql.NullString{String: expiresAt.Format(time.RFC3339), Valid: true}
	}

	query := `INSERT INTO policies (prefix, list, source, feed_id, expires_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(prefix, list) DO UPDATE SET source = excluded.source, feed_id = excluded.feed_id, expires_at = excluded.expires_at`
	if s.driver == "mysql" {
		query = `INSERT INTO policies (prefix, list, source, feed_id, expires_at) VALUES (?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE source = VALUES(source), feed_id = VALUES(feed_id), expires_at = VALUES(expires_at)`
	}

	_, err := s.db.ExecContext(ctx, query, prefix, list, source, feedID, expStr)
	return err
}

func (s *SQLStore) RemovePolicy(ctx context.Context, prefix, list string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE prefix = ? AND list = ?`, prefix, list)
	return err
}

func (s *SQLStore) BulkRemovePolicies(ctx context.Context, list string, prefixes []string) error {
	if len(prefixes) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `DELETE FROM policies WHERE prefix = ? AND list = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range prefixes {
		if _, err := stmt.ExecContext(ctx, p, list); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLStore) AllPrefixes(ctx context.Context, list string) ([]netip.Prefix, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT prefix FROM policies WHERE list = ?`, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var prefixes []netip.Prefix
	for rows.Next() {
		var str string
		if err := rows.Scan(&str); err == nil {
			if p, err := netip.ParsePrefix(str); err == nil {
				prefixes = append(prefixes, p)
			}
		}
	}
	return prefixes, rows.Err()
}

func (s *SQLStore) GetCounts(ctx context.Context) (int, int, error) {
	var bl, wl int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE list = 'blocklist'`).Scan(&bl)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE list = 'whitelist'`).Scan(&wl)
	return bl, wl, nil
}

func (s *SQLStore) RecordAudit(ctx context.Context, op, list, prefix string) error {
	nowMs := time.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs (timestamp_ms, operation, list, prefix) VALUES (?, ?, ?, ?)`, nowMs, op, list, prefix)
	return err
}

func (s *SQLStore) AuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT timestamp_ms, operation, list, prefix FROM audit_logs ORDER BY timestamp_ms DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var ms int64
		var op, list, pStr string
		if err := rows.Scan(&ms, &op, &list, &pStr); err == nil {
			if prefix, err := netip.ParsePrefix(pStr); err == nil {
				events = append(events, AuditEvent{
					Time:      time.UnixMilli(ms),
					Operation: op,
					List:      list,
					Prefix:    prefix,
				})
			}
		}
	}
	return events, rows.Err()
}
