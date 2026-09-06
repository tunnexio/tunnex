// Package dbcheck validates CP PostgreSQL connectivity without requiring a schema.
package dbcheck

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
)

// SafeError never includes driver messages: they can contain DSNs or server-controlled text.
func SafeError(err error) string {
	var dns *net.DNSError
	var cert *pgconn.PgError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var pqerr *pq.Error
	switch {
	case errors.As(err, &dns):
		return "database_dns_failed: check private DNS from the CP network"
	case errors.As(err, &unknown), errors.As(err, &hostname):
		return "database_tls_failed: check the CA, certificate hostname and TLS files"
	case errors.As(err, &cert):
		if strings.HasPrefix(cert.Code, "28") {
			return "database_auth_failed: check the database role and credential"
		}
		return "database_query_failed: check database permissions and server health"
	case errors.As(err, &pqerr):
		if strings.HasPrefix(string(pqerr.Code), "28") {
			return "database_auth_failed: check the database role and credential"
		}
		return "database_query_failed: check database permissions and server health"
	default:
		return "database_connection_failed: check private routing, firewall, TLS and credentials"
	}
}

// ValidateURL constrains the common URL contract used by pgx, libpq and pg_dump.
func ValidateURL(raw string, requireTLS bool) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || strings.Trim(u.Path, "/") == "" {
		return errors.New("database_url_invalid: provide a PostgreSQL URL with host and database")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || u.Fragment != "" {
		return errors.New("database_url_invalid: encode reserved characters and query parameters")
	}
	if requireTLS && query.Get("sslmode") != "verify-full" {
		return errors.New("database_tls_required: external PostgreSQL requires sslmode=verify-full")
	}
	for key, values := range query {
		if len(values) != 1 {
			return errors.New("database_url_invalid: duplicate connection parameters are not supported")
		}
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout", "application_name", "target_session_attrs":
		default:
			return errors.New("database_url_parameter_unsupported: use the documented common PostgreSQL URL parameters")
		}
	}
	return nil
}

// DumpEnvironment maps a URL to libpq variables. PGDATABASE itself does NOT
// expand a URI in pg_dump; passing the URI as argv would expose its password.
func DumpEnvironment(raw string, inherited []string) ([]string, error) {
	if err := ValidateURL(raw, false); err != nil {
		return nil, err
	}
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		return nil, errors.New("database_config_invalid")
	}
	u, _ := url.Parse(raw)
	env := make([]string, 0, len(inherited)+12)
	for _, value := range inherited {
		if !strings.HasPrefix(value, "PG") {
			env = append(env, value)
		}
	}
	env = append(env, "PGHOST="+cfg.Host, "PGPORT="+strconv.Itoa(int(cfg.Port)), "PGDATABASE="+cfg.Database,
		"PGUSER="+cfg.User, "PGPASSWORD="+cfg.Password, "PGCONNECT_TIMEOUT=10")
	for key, variable := range map[string]string{"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "application_name": "PGAPPNAME", "target_session_attrs": "PGTARGETSESSIONATTRS"} {
		if value := u.Query().Get(key); value != "" {
			env = append(env, variable+"="+value)
		}
	}
	return env, nil
}

// Run checks the actual drivers before migration. The timeout includes DNS and TLS.
// migration=true requires schema-create permission, but never creates a role or database.
func Run(parent context.Context, raw string, requireTLS, migration bool) error {
	if err := ValidateURL(raw, requireTLS); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		return errors.New("database_config_invalid: check URL parameters and TLS files")
	}
	cfg.ConnectTimeout = 10 * time.Second
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return errors.New(SafeError(err))
	}
	defer conn.Close(ctx)
	var version int
	var writable, schemaCreate, citextInstalled, citextAvailable, dbCreate bool
	err = conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int,
		NOT pg_is_in_recovery() AND current_setting('transaction_read_only') = 'off',
		has_schema_privilege(current_user, 'public', 'CREATE'),
		EXISTS (SELECT 1 FROM pg_extension WHERE extname='citext'),
		EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='citext'),
		has_database_privilege(current_user, current_database(), 'CREATE')`).Scan(
		&version, &writable, &schemaCreate, &citextInstalled, &citextAvailable, &dbCreate)
	if err != nil {
		return errors.New(SafeError(err))
	}
	if version < 160000 || version >= 170000 {
		return errors.New("database_version_unsupported: this BYODB release qualifies PostgreSQL 16")
	}
	if !writable {
		return errors.New("database_read_only: use the writable primary endpoint")
	}
	if migration && !schemaCreate {
		return errors.New("database_migration_permission_missing: migration role needs CREATE on public schema and ownership of Tunnex objects")
	}
	if migration {
		var foreignOwned bool
		err := conn.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v','m','f')
			AND NOT pg_has_role(current_user,c.relowner,'USAGE')
			AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_class'::regclass
			  AND d.objid=c.oid AND d.deptype='e'))`).Scan(&foreignOwned)
		if err != nil {
			return errors.New(SafeError(err))
		}
		if foreignOwned {
			return errors.New("database_migration_ownership_missing: migration role must own the existing Tunnex objects")
		}
	}
	if !citextInstalled && (!migration || !citextAvailable || !dbCreate) {
		return errors.New("database_extension_missing: ask your DBA to install citext in the Tunnex database")
	}
	// The migration driver is not pgx. Refuse incompatible URL options before DDL.
	if migration {
		db, err := sql.Open("postgres", raw)
		if err != nil {
			return errors.New("database_migration_connection_failed: check the common PostgreSQL URL parameters")
		}
		defer db.Close()
		if err := db.PingContext(ctx); err != nil {
			return errors.New("database_migration_connection_failed: check migration credentials, TLS and URL parameters")
		}
	}
	return nil
}
