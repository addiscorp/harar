//! The primary's secret store on Postgres (architecture, section 7).
//! Postgres holds ciphertext and names only: harar seals before writing and
//! opens after reading, and no key that decrypts anything ever reaches it.
//!
//! What a Postgres writer can't do without being noticed:
//! - change any column of a version (each one is bound into its encryption);
//! - move a ciphertext to another row;
//! - delete, add, or rewind any path's head, even to that path's own older,
//!   genuine head: every head's keyed share goes into one digest, tagged in
//!   the store's state row, and `load_all` recomputes it;
//! - roll the whole store back to an earlier genuine state: the primary keeps
//!   the number of writes it has made in an anchor file outside Postgres.

use super::envelope::{self, MasterKey, Row, Sealed};
use harar_client::model::{Org, valid_secret_path};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_postgres::config::Host;
use tokio_postgres::{Client, NoTls, Transaction};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum StoreError {
    BadOrg,
    BadPath,
    NotFound,
    /// Postgres can only be reached over a local socket or loopback.
    NotLocal,
    /// Another harar primary holds this store.
    InUse,
    /// The rows don't add up: something was changed outside harar.
    Tampered(String),
    Postgres(tokio_postgres::Error),
    Anchor(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::BadOrg => f.write_str("not an org name"),
            StoreError::BadPath => f.write_str("secret paths are /-separated segments, none empty, . or .."),
            StoreError::NotFound => f.write_str("no such secret"),
            StoreError::NotLocal => f.write_str("harar talks to Postgres only over a local socket or loopback, never unencrypted over a network"),
            StoreError::InUse => f.write_str("another harar primary is using this store"),
            StoreError::Tampered(what) => write!(f, "the secret store was changed outside harar: {what}"),
            StoreError::Postgres(err) => write!(f, "postgres: {err}"),
            StoreError::Anchor(err) => write!(f, "the store's anchor file: {err}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<tokio_postgres::Error> for StoreError {
    fn from(err: tokio_postgres::Error) -> StoreError {
        StoreError::Postgres(err)
    }
}

fn tampered(what: impl Into<String>) -> StoreError {
    StoreError::Tampered(what.into())
}

/// One stored version, without its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: u64,
    pub deleted: bool,
    pub written_by: String,
}

/// One write: a value, or a deletion when `value` is None.
pub struct Change<'a> {
    pub path: &'a str,
    pub value: Option<&'a [u8]>,
}

pub struct PgStore {
    client: Mutex<Client>,
    master: MasterKey,
    schema: String,
    /// Where the number of writes this primary has made is kept, outside
    /// Postgres. None in tests that don't exercise it.
    anchor: Option<PathBuf>,
}

fn check(org: &str, path: &str) -> Result<(), StoreError> {
    org.parse::<Org>().map_err(|_| StoreError::BadOrg)?;
    if !valid_secret_path(path) {
        return Err(StoreError::BadPath);
    }
    Ok(())
}

fn bytes32(value: &[u8], what: &str) -> Result<[u8; 32], StoreError> {
    value.try_into().map_err(|_| tampered(format!("{what} is not 32 bytes")))
}

struct State {
    seq: u64,
    digest: [u8; 32],
}

impl PgStore {
    /// Connects over a local socket or loopback, and creates the tables if
    /// they're missing. `schema` is normally `harar_primary`; tests give each
    /// run its own.
    pub async fn connect(url: &str, schema: &str, master: MasterKey, anchor: Option<PathBuf>) -> Result<PgStore, StoreError> {
        assert!(
            !schema.is_empty() && schema.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "schema names are fixed by harar, never taken from input"
        );
        let mut config: tokio_postgres::Config = url.parse()?;
        let local = !config.get_hosts().is_empty()
            && config.get_hosts().iter().all(|host| match host {
                Host::Unix(_) => true,
                Host::Tcp(name) => matches!(name.as_str(), "localhost" | "127.0.0.1" | "::1"),
            });
        if !local {
            return Err(StoreError::NotLocal);
        }
        config.connect_timeout(Duration::from_secs(10));
        config.keepalives(true);
        let (client, connection) = config.connect(NoTls).await?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                eprintln!("harar: postgres connection ended: {err}");
            }
        });
        client.batch_execute("SET statement_timeout = '10s'; SET lock_timeout = '10s'").await?;
        let store = PgStore { client: Mutex::new(client), master, schema: schema.to_string(), anchor };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        let s = &self.schema;
        let empty = envelope::state_tag(&self.master, 0, &[0; 32]);
        let client = self.client.lock().await;
        client
            .batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {s};
                 CREATE TABLE IF NOT EXISTS {s}.secrets (
                     org           text NOT NULL,
                     path          text NOT NULL,
                     version       bigint NOT NULL CHECK (version > 0),
                     ciphertext    bytea NOT NULL,
                     wrapped_key   bytea NOT NULL,
                     master_key_id text NOT NULL,
                     deleted       boolean NOT NULL,
                     written_by    text NOT NULL,
                     written_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
                     txn           text,
                     PRIMARY KEY (org, path, version)
                 );
                 CREATE TABLE IF NOT EXISTS {s}.secret_heads (
                     org     text NOT NULL,
                     path    text NOT NULL,
                     version bigint NOT NULL CHECK (version > 0),
                     tag     bytea NOT NULL,
                     PRIMARY KEY (org, path)
                 );
                 CREATE TABLE IF NOT EXISTS {s}.store_state (
                     one    boolean PRIMARY KEY DEFAULT true CHECK (one),
                     seq    bigint NOT NULL,
                     digest bytea NOT NULL,
                     tag    bytea NOT NULL
                 );"
            ))
            .await?;
        client
            .execute(
                &format!("INSERT INTO {s}.store_state (seq, digest, tag) VALUES (0, $1, $2) ON CONFLICT DO NOTHING"),
                &[&vec![0_u8; 32], &empty.to_vec()],
            )
            .await?;
        Ok(())
    }

    /// Takes the store for this process for as long as it's connected, so two
    /// primaries never serve one store with different views of it.
    pub async fn hold_as_primary(&self) -> Result<(), StoreError> {
        let held: bool = self
            .client
            .lock()
            .await
            .query_one("SELECT pg_try_advisory_lock(hashtextextended($1, 0))", &[&format!("harar:{}", self.schema)])
            .await?
            .get(0);
        if held { Ok(()) } else { Err(StoreError::InUse) }
    }

    async fn read_state(&self, tx: &Transaction<'_>, lock: bool) -> Result<State, StoreError> {
        let s = &self.schema;
        let row = tx
            .query_opt(&format!("SELECT seq, digest, tag FROM {s}.store_state WHERE one{}", if lock { " FOR UPDATE" } else { "" }), &[])
            .await?
            .ok_or_else(|| tampered("the store's state row is missing"))?;
        let seq: i64 = row.get(0);
        let digest = bytes32(row.get(1), "the store digest")?;
        let tag: &[u8] = row.get(2);
        if seq < 0 || !envelope::tags_match(tag, &envelope::state_tag(&self.master, seq as u64, &digest)) {
            return Err(tampered("the store's state row was not written by harar"));
        }
        self.check_anchor(seq as u64)?;
        Ok(State { seq: seq as u64, digest })
    }

    /// The anchor holds the number of writes this primary has made. Postgres
    /// may be ahead of it (a write committed, then a crash before the anchor
    /// moved), never behind.
    fn check_anchor(&self, seq: u64) -> Result<(), StoreError> {
        let Some(path) = &self.anchor else { return Ok(()) };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(StoreError::Anchor(err)),
        };
        let (seen, tag) = text.trim().split_once(' ').ok_or_else(|| tampered("the anchor file is malformed"))?;
        let seen: u64 = seen.parse().map_err(|_| tampered("the anchor file is malformed"))?;
        let tag: Vec<u8> = (0..tag.len())
            .step_by(2)
            .map(|i| tag.get(i..i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
            .collect::<Option<_>>()
            .ok_or_else(|| tampered("the anchor file is malformed"))?;
        if !envelope::tags_match(&tag, &envelope::anchor_tag(&self.master, seen)) {
            return Err(tampered("the anchor file was not written by harar"));
        }
        if seq < seen {
            return Err(tampered(format!("Postgres has seen {seq} writes, but this primary made {seen}: the store was rolled back")));
        }
        Ok(())
    }

    fn move_anchor(&self, seq: u64) -> Result<(), StoreError> {
        let Some(path) = &self.anchor else { return Ok(()) };
        let tag: String = envelope::anchor_tag(&self.master, seq).iter().map(|b| format!("{b:02x}")).collect();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, format!("{seq} {tag}\n")).map_err(StoreError::Anchor)?;
        std::fs::rename(&tmp, path).map_err(StoreError::Anchor)
    }

    /// Writes `changes` to one org, all or nothing, as new versions.
    pub async fn write(&self, org: &str, changes: &[Change<'_>], written_by: &str, txn: Option<&str>) -> Result<Vec<u64>, StoreError> {
        for change in changes {
            check(org, change.path)?;
        }
        let s = &self.schema;
        let mut client = self.client.lock().await;
        let tx = client.transaction().await?;
        let mut state = self.read_state(&tx, true).await?;
        let mut versions = Vec::with_capacity(changes.len());
        for change in changes {
            let head = tx
                .query_opt(&format!("SELECT version, tag FROM {s}.secret_heads WHERE org = $1 AND path = $2 FOR UPDATE"), &[&org, &change.path])
                .await?;
            let current = match &head {
                None => 0,
                Some(head) => {
                    let version = head.get::<_, i64>(0) as u64;
                    if !envelope::tags_match(head.get(1), &envelope::head_tag(&self.master, org, change.path, version)) {
                        return Err(tampered(format!("the head of {org}/{} was not written by harar", change.path)));
                    }
                    envelope::xor_into(&mut state.digest, &envelope::head_leaf(&self.master, org, change.path, version));
                    version
                }
            };
            let version = current + 1;
            let row = Row { org, path: change.path, version, deleted: change.value.is_none(), written_by, txn };
            let sealed = envelope::seal(&self.master, &row, change.value.unwrap_or_default());
            tx.execute(
                &format!(
                    "INSERT INTO {s}.secrets (org, path, version, ciphertext, wrapped_key, master_key_id, deleted, written_by, txn)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
                ),
                &[&org, &change.path, &(version as i64), &sealed.ciphertext, &sealed.wrapped_key, &sealed.master_key_id, &row.deleted, &written_by, &txn],
            )
            .await?;
            let tag = envelope::head_tag(&self.master, org, change.path, version).to_vec();
            tx.execute(
                &format!(
                    "INSERT INTO {s}.secret_heads (org, path, version, tag) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (org, path) DO UPDATE SET version = EXCLUDED.version, tag = EXCLUDED.tag"
                ),
                &[&org, &change.path, &(version as i64), &tag],
            )
            .await?;
            envelope::xor_into(&mut state.digest, &envelope::head_leaf(&self.master, org, change.path, version));
            versions.push(version);
        }
        state.seq += 1;
        let tag = envelope::state_tag(&self.master, state.seq, &state.digest).to_vec();
        tx.execute(&format!("UPDATE {s}.store_state SET seq = $1, digest = $2, tag = $3 WHERE one"), &[&(state.seq as i64), &state.digest.to_vec(), &tag])
            .await?;
        tx.commit().await?;
        self.move_anchor(state.seq)?;
        Ok(versions)
    }

    pub async fn put(&self, org: &str, path: &str, value: &[u8], written_by: &str, txn: Option<&str>) -> Result<u64, StoreError> {
        Ok(self.write(org, &[Change { path, value: Some(value) }], written_by, txn).await?[0])
    }

    /// Deletes by adding a version that holds nothing. History stays.
    pub async fn delete(&self, org: &str, path: &str, written_by: &str, txn: Option<&str>) -> Result<u64, StoreError> {
        Ok(self.write(org, &[Change { path, value: None }], written_by, txn).await?[0])
    }

    fn open_row(&self, org: &str, path: &str, version: u64, row: &tokio_postgres::Row) -> Result<(bool, Zeroizing<Vec<u8>>), StoreError> {
        let deleted: bool = row.get("deleted");
        let written_by: &str = row.get("written_by");
        let txn: Option<&str> = row.get("txn");
        let sealed = Sealed { ciphertext: row.get("ciphertext"), wrapped_key: row.get("wrapped_key"), master_key_id: row.get("master_key_id") };
        let value = envelope::open(&self.master, &Row { org, path, version, deleted, written_by, txn }, &sealed)
            .map_err(|err| tampered(format!("{org}/{path} version {version} {err}")))?;
        Ok((deleted, value))
    }

    /// Every live secret of `org`, newest versions, after checking the whole
    /// store: the state row's tag, the anchor, every head's tag, the digest
    /// over all heads, and that no secret exists without a head or past it.
    pub async fn load_all(&self, org: &str) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, StoreError> {
        org.parse::<Org>().map_err(|_| StoreError::BadOrg)?;
        let s = &self.schema;
        let mut client = self.client.lock().await;
        let tx = client.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).read_only(true).start().await?;
        let state = self.read_state(&tx, false).await?;
        let mut digest = [0_u8; 32];
        let mut heads = BTreeMap::new();
        for head in tx.query(&format!("SELECT org, path, version, tag FROM {s}.secret_heads"), &[]).await? {
            let (head_org, path, version): (String, String, i64) = (head.get(0), head.get(1), head.get(2));
            let version = version as u64;
            if !valid_secret_path(&path) || !envelope::tags_match(head.get(3), &envelope::head_tag(&self.master, &head_org, &path, version)) {
                return Err(tampered(format!("the head of {head_org}/{path} was not written by harar")));
            }
            envelope::xor_into(&mut digest, &envelope::head_leaf(&self.master, &head_org, &path, version));
            heads.insert((head_org, path), version);
        }
        if digest != state.digest {
            return Err(tampered("a head was added, removed or rewound"));
        }
        for row in tx.query(&format!("SELECT org, path, max(version) FROM {s}.secrets GROUP BY org, path"), &[]).await? {
            let key: (String, String) = (row.get(0), row.get(1));
            let newest = row.get::<_, i64>(2) as u64;
            if heads.get(&key) != Some(&newest) {
                return Err(tampered(format!("{}/{} has version {newest} but harar last wrote {:?}", key.0, key.1, heads.get(&key))));
            }
        }
        let mut out = BTreeMap::new();
        for ((head_org, path), version) in &heads {
            if head_org != org {
                continue;
            }
            let row = tx
                .query_opt(
                    &format!("SELECT ciphertext, wrapped_key, master_key_id, deleted, written_by, txn FROM {s}.secrets WHERE org = $1 AND path = $2 AND version = $3"),
                    &[&org, path, &(*version as i64)],
                )
                .await?
                .ok_or_else(|| tampered(format!("{org}/{path} version {version} is missing")))?;
            let (deleted, value) = self.open_row(org, path, *version, &row)?;
            if !deleted {
                out.insert(path.clone(), value);
            }
        }
        tx.commit().await?;
        Ok(out)
    }

    /// Paths under `prefix` (compared as text: pass a trailing `/` for a
    /// folder) whose newest version isn't a deletion. Checks the whole store.
    pub async fn list(&self, org: &str, prefix: &str) -> Result<Vec<String>, StoreError> {
        Ok(self.load_all(org).await?.into_keys().filter(|path| path.starts_with(prefix)).collect())
    }

    /// One path's newest value, checking that path's head and rows and the
    /// store's state row. A rewind to the path's own older head is caught by
    /// `load_all`, which the primary runs at every start.
    pub async fn get(&self, org: &str, path: &str) -> Result<(u64, Zeroizing<Vec<u8>>), StoreError> {
        check(org, path)?;
        let s = &self.schema;
        let mut client = self.client.lock().await;
        let tx = client.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).read_only(true).start().await?;
        self.read_state(&tx, false).await?;
        let head = tx.query_opt(&format!("SELECT version, tag FROM {s}.secret_heads WHERE org = $1 AND path = $2"), &[&org, &path]).await?;
        let newest: i64 = tx
            .query_one(&format!("SELECT coalesce(max(version), 0) FROM {s}.secrets WHERE org = $1 AND path = $2"), &[&org, &path])
            .await?
            .get(0);
        let Some(head) = head else {
            return Err(if newest == 0 { StoreError::NotFound } else { tampered(format!("{org}/{path} has versions but no head")) });
        };
        let version = head.get::<_, i64>(0) as u64;
        if !envelope::tags_match(head.get(1), &envelope::head_tag(&self.master, org, path, version)) {
            return Err(tampered(format!("the head of {org}/{path} was not written by harar")));
        }
        if newest as u64 != version {
            return Err(tampered(format!("{org}/{path} has version {newest} but harar last wrote {version}")));
        }
        let row = tx
            .query_opt(
                &format!("SELECT ciphertext, wrapped_key, master_key_id, deleted, written_by, txn FROM {s}.secrets WHERE org = $1 AND path = $2 AND version = $3"),
                &[&org, &path, &(version as i64)],
            )
            .await?
            .ok_or_else(|| tampered(format!("{org}/{path} version {version} is missing")))?;
        let (deleted, value) = self.open_row(org, path, version, &row)?;
        tx.commit().await?;
        if deleted {
            return Err(StoreError::NotFound);
        }
        Ok((version, value))
    }

    /// One version's value, for history and rollback on purpose.
    pub async fn get_version(&self, org: &str, path: &str, version: u64) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        check(org, path)?;
        let s = &self.schema;
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                &format!("SELECT ciphertext, wrapped_key, master_key_id, deleted, written_by, txn FROM {s}.secrets WHERE org = $1 AND path = $2 AND version = $3"),
                &[&org, &path, &(version as i64)],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let (deleted, value) = self.open_row(org, path, version, &row)?;
        if deleted {
            return Err(StoreError::NotFound);
        }
        Ok(value)
    }

    /// Every version of a path, each opened to prove its columns are harar's.
    pub async fn versions(&self, org: &str, path: &str) -> Result<Vec<VersionInfo>, StoreError> {
        check(org, path)?;
        let s = &self.schema;
        let rows = self
            .client
            .lock()
            .await
            .query(
                &format!("SELECT version, ciphertext, wrapped_key, master_key_id, deleted, written_by, txn FROM {s}.secrets WHERE org = $1 AND path = $2 ORDER BY version"),
                &[&org, &path],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let version = row.get::<_, i64>("version") as u64;
                let (deleted, _) = self.open_row(org, path, version, row)?;
                Ok(VersionInfo { version, deleted, written_by: row.get("written_by") })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A disposable Postgres, from `HARAR_TEST_DATABASE_URL`. Without one the
    /// tests fail, unless `HARAR_TEST_NO_POSTGRES` says this machine has none.
    fn database_url() -> Option<String> {
        match std::env::var("HARAR_TEST_DATABASE_URL") {
            Ok(url) => Some(url),
            Err(_) if std::env::var_os("HARAR_TEST_NO_POSTGRES").is_some() => {
                eprintln!("SKIPPED: no Postgres on this machine (HARAR_TEST_NO_POSTGRES)");
                None
            }
            Err(_) => panic!("set HARAR_TEST_DATABASE_URL to a disposable Postgres, or HARAR_TEST_NO_POSTGRES=1 where there is none"),
        }
    }

    /// Each test gets its own schema, so they run side by side.
    fn schema() -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        format!("harar_test_{}_{nanos}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn master() -> MasterKey {
        MasterKey::from_bytes("mk-1", [1; 32])
    }

    async fn store(url: &str, schema: &str) -> PgStore {
        PgStore::connect(url, schema, master(), None).await.unwrap()
    }

    async fn raw(url: &str) -> Client {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
        tokio::spawn(connection);
        client
    }

    const ORG: &str = "gg.addis";
    const PATH: &str = "prod/site/DATABASE_URL";
    const VALUE: &[u8] = b"postgres://app:hunter2-test@db/site";
    const SAMI: &str = "gg.addis.human.sami";

    fn is_tampered<T: fmt::Debug>(result: Result<T, StoreError>) -> bool {
        matches!(result, Err(StoreError::Tampered(_)))
    }

    #[tokio::test]
    async fn versions_are_kept_and_the_newest_wins() {
        let Some(url) = database_url() else { return };
        let store = store(&url, &schema()).await;
        assert_eq!(store.put(ORG, PATH, b"v1", SAMI, Some("01jbx5")).await.unwrap(), 1);
        assert_eq!(store.put(ORG, PATH, VALUE, SAMI, None).await.unwrap(), 2);
        let (version, value) = store.get(ORG, PATH).await.unwrap();
        assert_eq!((version, value.as_slice()), (2, VALUE));
        assert_eq!(store.get_version(ORG, PATH, 1).await.unwrap().as_slice(), b"v1");
        store.put(ORG, "prod/site/API_KEY", b"k", SAMI, None).await.unwrap();
        assert_eq!(store.list(ORG, "prod/site/").await.unwrap(), vec!["prod/site/API_KEY", PATH]);

        assert_eq!(store.delete(ORG, PATH, SAMI, None).await.unwrap(), 3);
        assert!(matches!(store.get(ORG, PATH).await, Err(StoreError::NotFound)));
        assert_eq!(store.list(ORG, "prod/site/").await.unwrap(), vec!["prod/site/API_KEY"]);
        assert_eq!(store.get_version(ORG, PATH, 2).await.unwrap().as_slice(), VALUE, "history stays");
        let versions = store.versions(ORG, PATH).await.unwrap();
        assert_eq!(versions.iter().map(|v| (v.version, v.deleted)).collect::<Vec<_>>(), [(1, false), (2, false), (3, true)]);
        assert!(matches!(store.get(ORG, "prod/never/written").await, Err(StoreError::NotFound)));
        let all = store.load_all(ORG).await.unwrap();
        assert_eq!(all.keys().collect::<Vec<_>>(), ["prod/site/API_KEY"]);
    }

    #[tokio::test]
    async fn postgres_never_sees_a_value() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let store = store(&url, &schema).await;
        store.put(ORG, PATH, VALUE, SAMI, None).await.unwrap();
        // Everything Postgres holds for this schema, as text, bytea in hex.
        let client = raw(&url).await;
        let mut dump = String::new();
        for table in ["secrets", "secret_heads", "store_state"] {
            for row in client.query(&format!("SELECT row_to_json(t)::text FROM {schema}.{table} t"), &[]).await.unwrap() {
                dump.push_str(row.get::<_, &str>(0));
            }
        }
        let hex: String = VALUE.iter().map(|b| format!("{b:02x}")).collect();
        assert!(dump.contains(PATH), "the dump is real");
        assert!(!dump.contains(std::str::from_utf8(VALUE).unwrap()) && !dump.contains(&hex), "the value is in no column");
        assert!(!dump.contains(&"01".repeat(32)), "nor is the master key");
    }

    #[tokio::test]
    async fn any_column_changed_outside_harar_is_caught() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let store = store(&url, &schema).await;
        store.put(ORG, PATH, VALUE, SAMI, Some("01jbx5")).await.unwrap();
        store.put(ORG, "prod/other/KEY", b"other", SAMI, None).await.unwrap();
        store.delete(ORG, "prod/gone/KEY", SAMI, None).await.ok();
        let client = raw(&url).await;
        let edit = |sql: String| {
            let client = &client;
            async move { client.batch_execute(&sql).await.unwrap() }
        };
        let s = &schema;
        for (change, undo) in [
            (format!("UPDATE {s}.secrets SET deleted = true WHERE path = '{PATH}'"), format!("UPDATE {s}.secrets SET deleted = false WHERE path = '{PATH}'")),
            (format!("UPDATE {s}.secrets SET written_by = 'gg.addis.agent.ava' WHERE path = '{PATH}'"), format!("UPDATE {s}.secrets SET written_by = '{SAMI}' WHERE path = '{PATH}'")),
            (format!("UPDATE {s}.secrets SET txn = '01jbx6' WHERE path = '{PATH}'"), format!("UPDATE {s}.secrets SET txn = '01jbx5' WHERE path = '{PATH}'")),
        ] {
            edit(change.clone()).await;
            assert!(is_tampered(store.get(ORG, PATH).await), "{change}");
            assert!(is_tampered(store.load_all(ORG).await), "{change}");
            edit(undo).await;
        }
        assert!(store.load_all(ORG).await.is_ok(), "every undo restored the original");

        // A deletion turned back into a live secret.
        store.delete(ORG, "prod/other/KEY", SAMI, None).await.unwrap();
        edit(format!("UPDATE {s}.secrets SET deleted = false WHERE path = 'prod/other/KEY' AND version = 2")).await;
        assert!(is_tampered(store.load_all(ORG).await), "a tombstone made live");
        edit(format!("UPDATE {s}.secrets SET deleted = true WHERE path = 'prod/other/KEY' AND version = 2")).await;

        // Another path's ciphertext copied over this one's.
        edit(format!(
            "UPDATE {s}.secrets t SET ciphertext = o.ciphertext, wrapped_key = o.wrapped_key
             FROM {s}.secrets o WHERE t.path = '{PATH}' AND o.path = 'prod/other/KEY' AND o.version = 1"
        ))
        .await;
        assert!(is_tampered(store.get(ORG, PATH).await), "a ciphertext moved between paths");
    }

    #[tokio::test]
    async fn heads_removed_added_or_rewound_are_caught() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let store = store(&url, &schema).await;
        let client = raw(&url).await;
        let s = &schema;
        store.put(ORG, PATH, b"v1", SAMI, None).await.unwrap();
        store.put(ORG, "prod/other/KEY", b"other", SAMI, None).await.unwrap();
        // A copy of this path's genuine head at version 1, taken before an update.
        let old_head: Vec<u8> = client.query_one(&format!("SELECT tag FROM {s}.secret_heads WHERE path = $1"), &[&PATH]).await.unwrap().get(0);
        store.put(ORG, PATH, VALUE, SAMI, None).await.unwrap();

        // Rewind: delete version 2 and put back the path's own old, genuine head.
        client.execute(&format!("DELETE FROM {s}.secrets WHERE path = $1 AND version = 2"), &[&PATH]).await.unwrap();
        client.execute(&format!("UPDATE {s}.secret_heads SET version = 1, tag = $2 WHERE path = $1"), &[&PATH, &old_head]).await.unwrap();
        assert!(is_tampered(store.load_all(ORG).await), "a path rewound to its own older head");
        store.put(ORG, "prod/new/KEY", b"x", SAMI, None).await.unwrap();
        assert!(is_tampered(store.load_all(ORG).await), "later writes don't paper over it");

        // A fresh store: removing a head makes its secret vanish, unless caught.
        let schema = format!("{s}_b");
        let store = super::tests::store(&url, &schema).await;
        let s = &schema;
        store.put(ORG, PATH, VALUE, SAMI, None).await.unwrap();
        store.put(ORG, "prod/other/KEY", b"other", SAMI, None).await.unwrap();
        client.execute(&format!("DELETE FROM {s}.secret_heads WHERE path = $1"), &[&PATH]).await.unwrap();
        assert!(is_tampered(store.load_all(ORG).await), "a removed head");
        assert!(is_tampered(store.get(ORG, PATH).await), "versions without a head");
    }

    #[tokio::test]
    async fn the_whole_store_rolled_back_is_caught_by_the_anchor() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let dir = tempfile::tempdir().unwrap();
        let anchor = dir.path().join("store.anchor");
        let store = PgStore::connect(&url, &schema, master(), Some(anchor.clone())).await.unwrap();
        let client = raw(&url).await;
        let s = &schema;
        store.put(ORG, PATH, b"v1", SAMI, None).await.unwrap();
        // A backup of every table, as genuine as it gets.
        client
            .batch_execute(&format!(
                "CREATE TABLE {s}.b_secrets AS SELECT * FROM {s}.secrets;
                 CREATE TABLE {s}.b_heads AS SELECT * FROM {s}.secret_heads;
                 CREATE TABLE {s}.b_state AS SELECT * FROM {s}.store_state;"
            ))
            .await
            .unwrap();
        store.put(ORG, PATH, VALUE, SAMI, None).await.unwrap();
        assert!(store.load_all(ORG).await.is_ok());
        client
            .batch_execute(&format!(
                "DELETE FROM {s}.secrets; INSERT INTO {s}.secrets SELECT * FROM {s}.b_secrets;
                 DELETE FROM {s}.secret_heads; INSERT INTO {s}.secret_heads SELECT * FROM {s}.b_heads;
                 DELETE FROM {s}.store_state; INSERT INTO {s}.store_state SELECT * FROM {s}.b_state;"
            ))
            .await
            .unwrap();
        let err = store.load_all(ORG).await.unwrap_err().to_string();
        assert!(err.contains("rolled back"), "{err}");

        // The anchor itself can't be edited down.
        std::fs::write(&anchor, "1 00\n").unwrap();
        assert!(is_tampered(store.load_all(ORG).await), "a forged anchor");
    }

    #[tokio::test]
    async fn a_write_of_several_changes_is_all_or_nothing() {
        let Some(url) = database_url() else { return };
        let store = store(&url, &schema()).await;
        let changes = [Change { path: "prod/a", value: Some(b"a") }, Change { path: "prod//bad", value: Some(b"b") }];
        assert!(matches!(store.write(ORG, &changes, SAMI, None).await, Err(StoreError::BadPath)));
        assert!(store.load_all(ORG).await.unwrap().is_empty(), "nothing was written");
        let changes = [Change { path: "prod/a", value: Some(b"a") }, Change { path: "prod/b", value: Some(b"b") }];
        assert_eq!(store.write(ORG, &changes, SAMI, None).await.unwrap(), [1, 1]);
        assert_eq!(store.load_all(ORG).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn concurrent_writers_get_distinct_versions() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        store(&url, &schema).await;
        let mut writers = Vec::new();
        for n in 0..8 {
            let (url, schema) = (url.clone(), schema.clone());
            writers.push(tokio::spawn(async move {
                let store = store(&url, &schema).await;
                store.put(ORG, PATH, format!("v{n}").as_bytes(), "gg.addis.service.ci", None).await
            }));
        }
        let mut versions = Vec::new();
        for writer in writers {
            versions.push(writer.await.unwrap().unwrap());
        }
        versions.sort();
        assert_eq!(versions, (1..=8).collect::<Vec<u64>>(), "eight writers, eight versions, none twice");
        assert!(store(&url, &schema).await.load_all(ORG).await.is_ok(), "the digest kept up");
    }

    #[tokio::test]
    async fn only_one_primary_holds_a_store() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let first = store(&url, &schema).await;
        first.hold_as_primary().await.unwrap();
        let second = store(&url, &schema).await;
        assert!(matches!(second.hold_as_primary().await, Err(StoreError::InUse)));
        drop(first);
        tokio::time::sleep(Duration::from_millis(200)).await;
        second.hold_as_primary().await.unwrap();
    }

    #[tokio::test]
    async fn postgres_is_reached_only_locally() {
        for url in ["host=db.example.com user=harar", "postgres://harar@10.0.0.5/harar", "user=harar"] {
            let result = PgStore::connect(url, "harar_primary", master(), None).await;
            assert!(matches!(result, Err(StoreError::NotLocal)), "{url}");
        }
    }

    #[tokio::test]
    async fn bad_names_never_reach_postgres() {
        let Some(url) = database_url() else { return };
        let store = store(&url, &schema()).await;
        assert!(matches!(store.put("addis", PATH, b"x", "x", None).await, Err(StoreError::BadOrg)));
        for path in ["prod/../admin", "prod//x", "", "/prod/x"] {
            assert!(matches!(store.put(ORG, path, b"x", "x", None).await, Err(StoreError::BadPath)), "{path:?}");
        }
    }
}
