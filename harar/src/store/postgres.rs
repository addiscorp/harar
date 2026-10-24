//! The primary's secret store on Postgres (architecture, section 7).
//! Postgres holds ciphertext and names only: harar seals before writing and
//! opens after reading, and no key that decrypts anything ever reaches it.

use super::envelope::{self, MasterKey, Sealed};
use harar_client::model::{Org, valid_secret_path};
use std::fmt;
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum StoreError {
    BadOrg,
    BadPath,
    NotFound,
    /// The rows don't add up: the newest version is missing, a head was moved
    /// or copied, or a ciphertext doesn't open where it sits.
    Tampered(String),
    Postgres(tokio_postgres::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::BadOrg => f.write_str("not an org name"),
            StoreError::BadPath => f.write_str("secret paths are /-separated segments, none empty, . or .."),
            StoreError::NotFound => f.write_str("no such secret"),
            StoreError::Tampered(what) => write!(f, "the secret store was changed outside harar: {what}"),
            StoreError::Postgres(err) => write!(f, "postgres: {err}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<tokio_postgres::Error> for StoreError {
    fn from(err: tokio_postgres::Error) -> StoreError {
        StoreError::Postgres(err)
    }
}

/// One stored version, without its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: u64,
    pub deleted: bool,
    pub written_by: String,
}

pub struct PgStore {
    client: Mutex<Client>,
    master: MasterKey,
    schema: String,
}

fn check(org: &str, path: &str) -> Result<(), StoreError> {
    org.parse::<Org>().map_err(|_| StoreError::BadOrg)?;
    if !valid_secret_path(path) {
        return Err(StoreError::BadPath);
    }
    Ok(())
}

impl PgStore {
    /// Connects and creates the tables if they're missing. `schema` is
    /// normally `harar_primary`; tests give each run its own.
    pub async fn connect(url: &str, schema: &str, master: MasterKey) -> Result<PgStore, StoreError> {
        assert!(
            !schema.is_empty() && schema.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "schema names are fixed by harar, never taken from input"
        );
        let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                eprintln!("harar: postgres connection ended: {err}");
            }
        });
        let store = PgStore { client: Mutex::new(client), master, schema: schema.to_string() };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        let s = &self.schema;
        self.client
            .lock()
            .await
            .batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {s};
                 CREATE TABLE IF NOT EXISTS {s}.secrets (
                     org           text NOT NULL,
                     path          text NOT NULL,
                     version       bigint NOT NULL CHECK (version > 0),
                     ciphertext    bytea NOT NULL,
                     wrapped_key   bytea NOT NULL,
                     master_key_id text NOT NULL,
                     deleted       boolean NOT NULL DEFAULT false,
                     written_by    text NOT NULL,
                     written_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
                     txn           text,
                     PRIMARY KEY (org, path, version)
                 );
                 CREATE TABLE IF NOT EXISTS {s}.secret_heads (
                     org     text NOT NULL,
                     path    text NOT NULL,
                     version bigint NOT NULL,
                     seal    bytea NOT NULL,
                     PRIMARY KEY (org, path)
                 );"
            ))
            .await?;
        Ok(())
    }

    /// Stores a new version and returns its number. Versions of one path are
    /// written one at a time; the head row's lock makes writers take turns.
    pub async fn put(&self, org: &str, path: &str, value: &[u8], written_by: &str, txn: Option<&str>) -> Result<u64, StoreError> {
        self.write(org, path, value, false, written_by, txn).await
    }

    /// Deletes by adding a version that holds nothing. History stays.
    pub async fn delete(&self, org: &str, path: &str, written_by: &str, txn: Option<&str>) -> Result<u64, StoreError> {
        self.write(org, path, b"", true, written_by, txn).await
    }

    async fn write(&self, org: &str, path: &str, value: &[u8], deleted: bool, written_by: &str, txn: Option<&str>) -> Result<u64, StoreError> {
        check(org, path)?;
        let s = &self.schema;
        let mut client = self.client.lock().await;
        let tx = client.transaction().await?;
        tx.execute(&format!("INSERT INTO {s}.secret_heads (org, path, version, seal) VALUES ($1, $2, 0, '') ON CONFLICT DO NOTHING"), &[&org, &path])
            .await?;
        let head = tx
            .query_one(&format!("SELECT version, seal FROM {s}.secret_heads WHERE org = $1 AND path = $2 FOR UPDATE"), &[&org, &path])
            .await?;
        let current: i64 = head.get(0);
        if current > 0 && !envelope::head_is_genuine(&self.master, org, path, current as u64, head.get(1)) {
            return Err(StoreError::Tampered(format!("the head of {org}/{path} was not written by harar")));
        }
        let version = current as u64 + 1;
        let sealed = envelope::seal(&self.master, org, path, version, value);
        tx.execute(
            &format!(
                "INSERT INTO {s}.secrets (org, path, version, ciphertext, wrapped_key, master_key_id, deleted, written_by, txn)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            ),
            &[&org, &path, &(version as i64), &sealed.ciphertext, &sealed.wrapped_key, &sealed.master_key_id, &deleted, &written_by, &txn],
        )
        .await?;
        let seal = envelope::seal_head(&self.master, org, path, version);
        tx.execute(&format!("UPDATE {s}.secret_heads SET version = $3, seal = $4 WHERE org = $1 AND path = $2"), &[&org, &path, &(version as i64), &seal])
            .await?;
        tx.commit().await?;
        Ok(version)
    }

    /// The newest version's value, after checking the head is harar's and no
    /// row newer than it exists.
    pub async fn get(&self, org: &str, path: &str) -> Result<(u64, Zeroizing<Vec<u8>>), StoreError> {
        check(org, path)?;
        let s = &self.schema;
        let client = self.client.lock().await;
        let head = client
            .query_opt(&format!("SELECT version, seal FROM {s}.secret_heads WHERE org = $1 AND path = $2"), &[&org, &path])
            .await?
            .ok_or(StoreError::NotFound)?;
        let version: i64 = head.get(0);
        if version == 0 {
            return Err(StoreError::NotFound);
        }
        if !envelope::head_is_genuine(&self.master, org, path, version as u64, head.get(1)) {
            return Err(StoreError::Tampered(format!("the head of {org}/{path} was not written by harar")));
        }
        let newest: i64 = client
            .query_one(&format!("SELECT coalesce(max(version), 0) FROM {s}.secrets WHERE org = $1 AND path = $2"), &[&org, &path])
            .await?
            .get(0);
        if newest != version {
            return Err(StoreError::Tampered(format!("{org}/{path} has version {newest} but harar last wrote {version}")));
        }
        drop(client);
        let (deleted, value) = self.open_version(org, path, version as u64).await?;
        if deleted {
            return Err(StoreError::NotFound);
        }
        Ok((version as u64, value))
    }

    /// One version's value, for history and rollback-on-purpose.
    pub async fn get_version(&self, org: &str, path: &str, version: u64) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        check(org, path)?;
        let (deleted, value) = self.open_version(org, path, version).await?;
        if deleted {
            return Err(StoreError::NotFound);
        }
        Ok(value)
    }

    async fn open_version(&self, org: &str, path: &str, version: u64) -> Result<(bool, Zeroizing<Vec<u8>>), StoreError> {
        let s = &self.schema;
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                &format!("SELECT ciphertext, wrapped_key, master_key_id, deleted FROM {s}.secrets WHERE org = $1 AND path = $2 AND version = $3"),
                &[&org, &path, &(version as i64)],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let sealed = Sealed { ciphertext: row.get(0), wrapped_key: row.get(1), master_key_id: row.get(2) };
        let value = envelope::open(&self.master, org, path, version, &sealed)
            .map_err(|err| StoreError::Tampered(format!("{org}/{path} version {version} {err}")))?;
        Ok((row.get(3), value))
    }

    pub async fn versions(&self, org: &str, path: &str) -> Result<Vec<VersionInfo>, StoreError> {
        check(org, path)?;
        let s = &self.schema;
        let rows = self
            .client
            .lock()
            .await
            .query(&format!("SELECT version, deleted, written_by FROM {s}.secrets WHERE org = $1 AND path = $2 ORDER BY version"), &[&org, &path])
            .await?;
        Ok(rows
            .iter()
            .map(|row| VersionInfo { version: row.get::<_, i64>(0) as u64, deleted: row.get(1), written_by: row.get(2) })
            .collect())
    }

    /// Paths under `prefix` whose newest version isn't a deletion.
    pub async fn list(&self, org: &str, prefix: &str) -> Result<Vec<String>, StoreError> {
        org.parse::<Org>().map_err(|_| StoreError::BadOrg)?;
        let s = &self.schema;
        let rows = self
            .client
            .lock()
            .await
            .query(
                &format!(
                    "SELECT h.path FROM {s}.secret_heads h JOIN {s}.secrets v USING (org, path, version)
                     WHERE h.org = $1 AND starts_with(h.path, $2) AND NOT v.deleted ORDER BY h.path"
                ),
                &[&org, &prefix],
            )
            .await?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
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
            Err(_) if std::env::var_os("HARAR_TEST_NO_POSTGRES").is_some() => None,
            Err(_) => panic!("set HARAR_TEST_DATABASE_URL to a disposable Postgres, or HARAR_TEST_NO_POSTGRES=1 where there is none"),
        }
    }

    /// Each test gets its own schema, so they run side by side.
    fn schema() -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!("harar_test_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
    }

    async fn store(url: &str, schema: &str, master: MasterKey) -> PgStore {
        PgStore::connect(url, schema, master).await.unwrap()
    }

    async fn raw(url: &str) -> Client {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
        tokio::spawn(connection);
        client
    }

    const ORG: &str = "gg.addis";
    const PATH: &str = "prod/site/DATABASE_URL";
    const VALUE: &[u8] = b"postgres://app:hunter2-test@db/site";

    #[tokio::test]
    async fn versions_are_kept_and_the_newest_wins() {
        let Some(url) = database_url() else { return };
        let store = store(&url, &schema(), MasterKey::from_bytes("mk-1", [1; 32])).await;
        assert_eq!(store.put(ORG, PATH, b"v1", "gg.addis.human.sami", Some("01jbx5")).await.unwrap(), 1);
        assert_eq!(store.put(ORG, PATH, VALUE, "gg.addis.human.sami", None).await.unwrap(), 2);
        let (version, value) = store.get(ORG, PATH).await.unwrap();
        assert_eq!((version, value.as_slice()), (2, VALUE));
        assert_eq!(store.get_version(ORG, PATH, 1).await.unwrap().as_slice(), b"v1");
        store.put(ORG, "prod/site/API_KEY", b"k", "gg.addis.human.sami", None).await.unwrap();
        assert_eq!(store.list(ORG, "prod/site/").await.unwrap(), vec!["prod/site/API_KEY", PATH]);

        assert_eq!(store.delete(ORG, PATH, "gg.addis.human.sami", None).await.unwrap(), 3);
        assert!(matches!(store.get(ORG, PATH).await, Err(StoreError::NotFound)));
        assert_eq!(store.list(ORG, "prod/site/").await.unwrap(), vec!["prod/site/API_KEY"]);
        assert_eq!(store.get_version(ORG, PATH, 2).await.unwrap().as_slice(), VALUE, "history stays");
        let versions = store.versions(ORG, PATH).await.unwrap();
        assert_eq!(versions.iter().map(|v| (v.version, v.deleted)).collect::<Vec<_>>(), [(1, false), (2, false), (3, true)]);
        assert!(matches!(store.get(ORG, "prod/never/written").await, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn postgres_never_sees_a_value() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let store = store(&url, &schema, MasterKey::from_bytes("mk-1", [1; 32])).await;
        store.put(ORG, PATH, VALUE, "gg.addis.human.sami", None).await.unwrap();
        // Everything Postgres holds for this schema, as text, bytea in hex.
        let client = raw(&url).await;
        let mut dump = String::new();
        for table in ["secrets", "secret_heads"] {
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
    async fn rows_changed_outside_harar_are_caught() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        let store = store(&url, &schema, MasterKey::from_bytes("mk-1", [1; 32])).await;
        store.put(ORG, PATH, b"v1", "gg.addis.human.sami", None).await.unwrap();
        store.put(ORG, PATH, VALUE, "gg.addis.human.sami", None).await.unwrap();
        store.put(ORG, "prod/other/KEY", b"other", "gg.addis.human.sami", None).await.unwrap();
        let client = raw(&url).await;
        let tampered = |result: Result<(u64, Zeroizing<Vec<u8>>), StoreError>| matches!(result, Err(StoreError::Tampered(_)));

        // Another path's ciphertext copied over this one's.
        client
            .execute(
                &format!(
                    "UPDATE {schema}.secrets t SET ciphertext = o.ciphertext, wrapped_key = o.wrapped_key
                     FROM {schema}.secrets o WHERE t.path = $1 AND t.version = 2 AND o.path = 'prod/other/KEY'"
                ),
                &[&PATH],
            )
            .await
            .unwrap();
        assert!(tampered(store.get(ORG, PATH).await), "a ciphertext moved between paths");

        // The newest version deleted, so the old one would show.
        client.execute(&format!("DELETE FROM {schema}.secrets WHERE path = $1 AND version = 2"), &[&PATH]).await.unwrap();
        assert!(tampered(store.get(ORG, PATH).await), "the newest version removed");

        // The head pointed back at version 1 with another path's tag.
        client
            .execute(
                &format!("UPDATE {schema}.secret_heads t SET version = 1, seal = o.seal FROM {schema}.secret_heads o WHERE t.path = $1 AND o.path = 'prod/other/KEY'"),
                &[&PATH],
            )
            .await
            .unwrap();
        assert!(tampered(store.get(ORG, PATH).await), "a head copied from another path");
        assert!(matches!(store.put(ORG, PATH, b"v3", "gg.addis.human.sami", None).await, Err(StoreError::Tampered(_))), "writes refuse a forged head too");

        // A different master key opens nothing.
        let other = PgStore::connect(&url, &schema, MasterKey::from_bytes("mk-1", [2; 32])).await.unwrap();
        assert!(tampered(other.get(ORG, "prod/other/KEY").await));
    }

    #[tokio::test]
    async fn concurrent_writers_get_distinct_versions() {
        let Some(url) = database_url() else { return };
        let schema = schema();
        store(&url, &schema, MasterKey::from_bytes("mk-1", [1; 32])).await;
        let mut writers = Vec::new();
        for n in 0..8 {
            let (url, schema) = (url.clone(), schema.clone());
            writers.push(tokio::spawn(async move {
                let store = store(&url, &schema, MasterKey::from_bytes("mk-1", [1; 32])).await;
                store.put(ORG, PATH, format!("v{n}").as_bytes(), "gg.addis.service.ci", None).await
            }));
        }
        let mut versions = Vec::new();
        for writer in writers {
            versions.push(writer.await.unwrap().unwrap());
        }
        versions.sort();
        assert_eq!(versions, (1..=8).collect::<Vec<u64>>(), "eight writers, eight versions, none twice");
    }

    #[tokio::test]
    async fn bad_names_never_reach_postgres() {
        let Some(url) = database_url() else { return };
        let store = store(&url, &schema(), MasterKey::from_bytes("mk-1", [1; 32])).await;
        assert!(matches!(store.put("addis", PATH, b"x", "x", None).await, Err(StoreError::BadOrg)));
        for path in ["prod/../admin", "prod//x", "", "/prod/x"] {
            assert!(matches!(store.put(ORG, path, b"x", "x", None).await, Err(StoreError::BadPath)), "{path:?}");
        }
    }
}
