package keys

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	store := &Store{db: db}

	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := store.seedIfNeeded(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) init() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	return err
}

func (s *Store) seedIfNeeded() error {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	now := time.Now().UTC()

	expiredPriv, err := GenerateRSAKey()
	if err != nil {
		return err
	}

	validPriv, err := GenerateRSAKey()
	if err != nil {
		return err
	}

	expiredPEM, err := EncodePrivateKeyToPEM(expiredPriv)
	if err != nil {
		return err
	}

	validPEM, err := EncodePrivateKeyToPEM(validPriv)
	if err != nil {
		return err
	}

	if err := s.InsertKey(expiredPEM, now.Add(-1*time.Hour)); err != nil {
		return err
	}

	if err := s.InsertKey(validPEM, now.Add(24*time.Hour)); err != nil {
		return err
	}

	return nil
}

func (s *Store) InsertKey(privateKeyPEM []byte, exp time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO keys (key, exp) VALUES (?, ?)`,
		privateKeyPEM,
		exp.UTC().Unix(),
	)
	return err
}

func (s *Store) GetValidKey(now time.Time) (KeyRecord, bool, error) {
	row := s.db.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1`,
		now.UTC().Unix(),
	)

	var kid int64
	var pemBytes []byte
	var expUnix int64

	err := row.Scan(&kid, &pemBytes, &expUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KeyRecord{}, false, nil
		}
		return KeyRecord{}, false, err
	}

	priv, err := DecodePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return KeyRecord{}, false, err
	}

	return KeyRecord{
		KID:    kid,
		Expiry: time.Unix(expUnix, 0).UTC(),
		Priv:   priv,
	}, true, nil
}

func (s *Store) GetExpiredKey(now time.Time) (KeyRecord, bool, error) {
	row := s.db.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1`,
		now.UTC().Unix(),
	)

	var kid int64
	var pemBytes []byte
	var expUnix int64

	err := row.Scan(&kid, &pemBytes, &expUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KeyRecord{}, false, nil
		}
		return KeyRecord{}, false, err
	}

	priv, err := DecodePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return KeyRecord{}, false, err
	}

	return KeyRecord{
		KID:    kid,
		Expiry: time.Unix(expUnix, 0).UTC(),
		Priv:   priv,
	}, true, nil
}

func (s *Store) ActiveKeys(now time.Time) ([]KeyRecord, error) {
	rows, err := s.db.Query(
		`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid`,
		now.UTC().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KeyRecord

	for rows.Next() {
		var kid int64
		var pemBytes []byte
		var expUnix int64

		if err := rows.Scan(&kid, &pemBytes, &expUnix); err != nil {
			return nil, err
		}

		priv, err := DecodePrivateKeyFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}

		out = append(out, KeyRecord{
			KID:    kid,
			Expiry: time.Unix(expUnix, 0).UTC(),
			Priv:   priv,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
