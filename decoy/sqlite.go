package decoy

import (
	"database/sql"
	"encoding/json"
	"time"
)

// SQLiteStore persists Decoy deployments and trips so armed traps survive a
// restart and trip history is retained. It lives in the decoy package (not the
// store package) to avoid an import cycle — decoy already depends on store.
// It shares the same *sql.DB as the findings store.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore migrates the decoy tables and returns the store.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS decoy_deployments (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    port       INTEGER NOT NULL DEFAULT 0,
    service    TEXT NOT NULL DEFAULT '',
    host       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS decoy_trips (
    id            TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    kind          TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    at            TIMESTAMP NOT NULL,
    source_ip     TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_decoy_trips_dep ON decoy_trips(deployment_id);`); err != nil {
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) PutDeployment(d Deployment) error {
	_, err := s.db.Exec(`
INSERT INTO decoy_deployments (id, kind, label, port, service, host, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    kind = excluded.kind, label = excluded.label, port = excluded.port,
    service = excluded.service, host = excluded.host, created_at = excluded.created_at`,
		d.ID, string(d.Kind), d.Label, d.Port, d.Service, d.Host, d.CreatedAt.UTC())
	return err
}

func (s *SQLiteStore) GetDeployment(id string) (Deployment, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, kind, label, port, service, host, created_at FROM decoy_deployments WHERE id = ?`, id)
	d, err := scanDeployment(row)
	if err == sql.ErrNoRows {
		return Deployment{}, false, nil
	}
	if err != nil {
		return Deployment{}, false, err
	}
	return d, true, nil
}

func (s *SQLiteStore) ListDeployments() ([]Deployment, error) {
	rows, err := s.db.Query(
		`SELECT id, kind, label, port, service, host, created_at FROM decoy_deployments ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteDeployment(id string) error {
	_, err := s.db.Exec(`DELETE FROM decoy_deployments WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) PutTrip(t Trip) error {
	detail := "{}"
	if t.Detail != nil {
		if b, err := json.Marshal(t.Detail); err == nil {
			detail = string(b)
		}
	}
	_, err := s.db.Exec(`
INSERT INTO decoy_trips (id, deployment_id, kind, label, at, source_ip, detail)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO NOTHING`,
		t.ID, t.DeploymentID, string(t.Kind), t.Label, t.At.UTC(), t.SourceIP, detail)
	return err
}

func (s *SQLiteStore) ListTrips() ([]Trip, error) {
	rows, err := s.db.Query(
		`SELECT id, deployment_id, kind, label, at, source_ip, detail FROM decoy_trips ORDER BY at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTrips(rows)
}

func (s *SQLiteStore) ListTripsFor(deploymentID string) ([]Trip, error) {
	rows, err := s.db.Query(
		`SELECT id, deployment_id, kind, label, at, source_ip, detail FROM decoy_trips WHERE deployment_id = ? ORDER BY at DESC`,
		deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTrips(rows)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDeployment(sc scanner) (Deployment, error) {
	var d Deployment
	var kind string
	var created time.Time
	if err := sc.Scan(&d.ID, &kind, &d.Label, &d.Port, &d.Service, &d.Host, &created); err != nil {
		return Deployment{}, err
	}
	d.Kind = TrapKind(kind)
	d.CreatedAt = created
	return d, nil
}

func scanTrips(rows *sql.Rows) ([]Trip, error) {
	var out []Trip
	for rows.Next() {
		var t Trip
		var kind, detail string
		var at time.Time
		if err := rows.Scan(&t.ID, &t.DeploymentID, &kind, &t.Label, &at, &t.SourceIP, &detail); err != nil {
			return nil, err
		}
		t.Kind = TrapKind(kind)
		t.At = at
		if detail != "" && detail != "{}" {
			_ = json.Unmarshal([]byte(detail), &t.Detail)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
