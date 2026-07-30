use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, SessionEvent, SessionEventKind,
    SessionId, SessionListCursor, SessionListItem, SessionListScope, SessionOverviewItem,
    SessionOverviewOrder, SessionSnapshot, SessionStateEffect,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

const DATABASE_FILE_NAME: &str = "caushell.sqlite3";
const SESSION_LOGS_DIR_NAME: &str = "session-logs";
const LOG_SYNC_EVENT_INTERVAL: u64 = 25;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
const STORE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    session_id TEXT NOT NULL,
    event_index INTEGER NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    sequence_no INTEGER,
    command TEXT,
    decision TEXT,
    finding_count INTEGER,
    evidence_count INTEGER,
    has_derived_invocations INTEGER,
    has_nested_payloads INTEGER,
    has_execution_payload_sink INTEGER,
    has_startup_config_load INTEGER,
    has_interactive_escape INTEGER,
    workspace_root TEXT,
    runtime_name TEXT,
    raw_event_json TEXT NOT NULL,
    PRIMARY KEY (session_id, event_index)
);

CREATE TABLE IF NOT EXISTS snapshots (
    session_id TEXT PRIMARY KEY,
    last_event_index INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS events_tail_idx
ON events(session_id, event_index);

CREATE INDEX IF NOT EXISTS events_overview_seq_idx
ON events(session_id, kind, sequence_no);

CREATE INDEX IF NOT EXISTS events_overview_time_idx
ON events(session_id, kind, observed_at_ms);

CREATE INDEX IF NOT EXISTS events_session_list_idx
ON events(session_id, observed_at_ms);

CREATE INDEX IF NOT EXISTS events_session_workspace_idx
ON events(kind, workspace_root, observed_at_ms, session_id);
"#;

#[derive(Debug)]
pub enum SessionStoreError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Encode(serde_json::Error),
    Decode(serde_json::Error),
    Clock(std::time::SystemTimeError),
    InvalidDecision(String),
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "caushell-store I/O failure: {error}"),
            Self::Sqlite(error) => write!(f, "caushell-store SQLite failure: {error}"),
            Self::Encode(error) => write!(f, "caushell-store JSON encode failure: {error}"),
            Self::Decode(error) => write!(f, "caushell-store JSON decode failure: {error}"),
            Self::Clock(error) => write!(f, "caushell-store clock failure: {error}"),
            Self::InvalidDecision(value) => {
                write!(f, "caushell-store invalid stored decision value: {value}")
            }
        }
    }
}

impl std::error::Error for SessionStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Clock(error) => Some(error),
            Self::InvalidDecision(_) => None,
        }
    }
}

impl From<std::io::Error> for SessionStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for SessionStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    root_dir: PathBuf,
}

#[derive(Debug)]
pub struct SessionStoreMaterializer {
    store: SessionStore,
    conn: Connection,
}

#[derive(Debug)]
pub struct SessionLogWriter {
    store: SessionStore,
    files: BTreeMap<SessionId, File>,
    unsynced_event_counts: BTreeMap<SessionId, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOverviewPageRequest {
    pub session_id: SessionId,
    pub limit: usize,
    pub before_sequence: Option<CommandSequenceNo>,
    pub after_sequence: Option<CommandSequenceNo>,
    pub order: SessionOverviewOrder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOverviewPage {
    pub items: Vec<SessionOverviewItem>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCheckDetail {
    pub session_id: SessionId,
    pub sequence_no: CommandSequenceNo,
    pub event_index: u64,
    pub observed_at_ms: u64,
    pub request: CheckRequest,
    pub response: CheckResponse,
    pub state_effect: SessionStateEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListPageRequest {
    pub limit: usize,
    pub cursor: Option<SessionListCursor>,
    pub workspace_root: Option<String>,
    pub scope: SessionListScope,
    pub order: SessionOverviewOrder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListPage {
    pub items: Vec<SessionListItem>,
    pub has_more: bool,
    pub next_cursor: Option<SessionListCursor>,
}

#[derive(Debug)]
struct EventProjection {
    kind: &'static str,
    sequence_no: Option<i64>,
    command: Option<String>,
    decision: Option<&'static str>,
    finding_count: Option<i64>,
    evidence_count: Option<i64>,
    has_derived_invocations: Option<i64>,
    has_nested_payloads: Option<i64>,
    has_execution_payload_sink: Option<i64>,
    has_startup_config_load: Option<i64>,
    has_interactive_escape: Option<i64>,
    workspace_root: Option<String>,
    runtime_name: Option<String>,
}

impl EventProjection {
    fn from_event(event: &SessionEvent) -> Self {
        match &event.kind {
            SessionEventKind::Check {
                request, response, ..
            } => {
                let trace = &response.decision_trace;
                Self {
                    kind: "check",
                    sequence_no: Some(request.sequence_no.0 as i64),
                    command: Some(request.command.clone()),
                    decision: Some(decision_to_str(response.decision)),
                    finding_count: Some(trace.findings.len() as i64),
                    evidence_count: Some(trace.evidence.len() as i64),
                    has_derived_invocations: Some(bool_to_i64(
                        !trace.derived_invocations.is_empty(),
                    )),
                    has_nested_payloads: Some(bool_to_i64(!trace.nested_payloads.is_empty())),
                    has_execution_payload_sink: Some(bool_to_i64(
                        trace
                            .execution_semantics
                            .iter()
                            .any(|semantics| semantics.executes_payload),
                    )),
                    has_startup_config_load: Some(bool_to_i64(
                        trace
                            .execution_semantics
                            .iter()
                            .any(|semantics| semantics.loads_startup_config),
                    )),
                    has_interactive_escape: Some(bool_to_i64(
                        trace
                            .execution_semantics
                            .iter()
                            .any(|semantics| semantics.opens_interactive_escape_surface),
                    )),
                    workspace_root: request.workspace_root.clone(),
                    runtime_name: Some(request.runtime.runtime_name.clone()),
                }
            }
            SessionEventKind::ShellStateDelta { .. } => Self {
                kind: "shell_state_delta",
                sequence_no: None,
                command: None,
                decision: None,
                finding_count: None,
                evidence_count: None,
                has_derived_invocations: None,
                has_nested_payloads: None,
                has_execution_payload_sink: None,
                has_startup_config_load: None,
                has_interactive_escape: None,
                workspace_root: None,
                runtime_name: None,
            },
        }
    }
}

impl SessionStore {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn database_path(&self) -> PathBuf {
        self.root_dir.join(DATABASE_FILE_NAME)
    }

    pub fn initialize_database(&self) -> Result<(), SessionStoreError> {
        self.ensure_private_directories()?;
        self.migrate_existing_log_permissions()?;
        ensure_private_file_exists(&self.database_path())?;
        self.secure_database_files()?;

        let conn = Connection::open(self.database_path())?;
        configure_connection(&conn)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(STORE_SCHEMA_SQL)?;
        ensure_store_schema(&conn)?;
        self.secure_database_files()?;

        Ok(())
    }

    pub fn open_materializer(&self) -> Result<SessionStoreMaterializer, SessionStoreError> {
        Ok(SessionStoreMaterializer {
            store: self.clone(),
            conn: self.open_existing_connection()?,
        })
    }

    pub fn open_log_writer(&self) -> Result<SessionLogWriter, SessionStoreError> {
        self.ensure_private_directories()?;
        self.migrate_existing_log_permissions()?;
        Ok(SessionLogWriter {
            store: self.clone(),
            files: BTreeMap::new(),
            unsynced_event_counts: BTreeMap::new(),
        })
    }

    pub fn open_connection(&self) -> Result<Connection, SessionStoreError> {
        self.open_existing_connection()
    }

    pub fn append_event(&self, event: &SessionEvent) -> Result<(), SessionStoreError> {
        self.append_log_event(event)?;
        if !self.database_exists() {
            self.initialize_database()?;
        }
        let conn = self.open_existing_connection()?;
        self.materialize_event_with_connection(&conn, event)
    }

    pub fn append_log_event(&self, event: &SessionEvent) -> Result<(), SessionStoreError> {
        self.ensure_private_directories()?;
        let mut file = open_private_append(&self.session_log_path(&event.session_id))?;
        append_event_jsonl(&mut file, event)
    }

    pub fn materialize_event_with_connection(
        &self,
        conn: &Connection,
        event: &SessionEvent,
    ) -> Result<(), SessionStoreError> {
        let raw_event_json = serde_json::to_string(event).map_err(SessionStoreError::Encode)?;
        let projection = EventProjection::from_event(event);

        conn.execute(
            r#"
            INSERT INTO events (
                session_id,
                event_index,
                observed_at_ms,
                kind,
                sequence_no,
                command,
                decision,
                finding_count,
                evidence_count,
                has_derived_invocations,
                has_nested_payloads,
                has_execution_payload_sink,
                has_startup_config_load,
                has_interactive_escape,
                workspace_root,
                runtime_name,
                raw_event_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            "#,
            params![
                event.session_id.0.as_str(),
                event.event_index as i64,
                event.observed_at_ms as i64,
                projection.kind,
                projection.sequence_no,
                projection.command,
                projection.decision,
                projection.finding_count,
                projection.evidence_count,
                projection.has_derived_invocations,
                projection.has_nested_payloads,
                projection.has_execution_payload_sink,
                projection.has_startup_config_load,
                projection.has_interactive_escape,
                projection.workspace_root,
                projection.runtime_name,
                raw_event_json,
            ],
        )?;

        Ok(())
    }

    pub fn read_events(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<SessionEvent>, SessionStoreError> {
        self.read_log_events(session_id, 0)
    }

    pub fn read_events_after(
        &self,
        session_id: &SessionId,
        after_event_index: u64,
    ) -> Result<Vec<SessionEvent>, SessionStoreError> {
        self.read_log_events(session_id, after_event_index)
    }

    pub fn replace_session_log(
        &self,
        session_id: &SessionId,
        events: &[SessionEvent],
    ) -> Result<(), SessionStoreError> {
        self.ensure_private_directories()?;
        let path = self.session_log_path(session_id);

        if events.is_empty() {
            match fs::remove_file(&path) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(SessionStoreError::Io(error)),
            }
        }

        let temp_path = path.with_extension("jsonl.repair.tmp");
        {
            let mut temp_file = open_private_truncate(&temp_path)?;
            for event in events {
                append_event_jsonl(&mut temp_file, event)?;
            }
            temp_file.sync_data()?;
        }

        fs::rename(&temp_path, &path)?;
        Ok(())
    }

    pub fn clear_session_materialized_state(
        &self,
        session_id: &SessionId,
    ) -> Result<(), SessionStoreError> {
        if !self.database_exists() {
            return Ok(());
        }

        let conn = self.open_existing_connection()?;
        conn.execute(
            "DELETE FROM events WHERE session_id = ?1",
            params![session_id.0.as_str()],
        )?;
        conn.execute(
            "DELETE FROM snapshots WHERE session_id = ?1",
            params![session_id.0.as_str()],
        )?;

        Ok(())
    }

    pub fn read_session_overview_page(
        &self,
        request: &SessionOverviewPageRequest,
    ) -> Result<SessionOverviewPage, SessionStoreError> {
        if !self.database_exists() {
            return Ok(SessionOverviewPage {
                items: Vec::new(),
                has_more: false,
            });
        }

        let conn = self.open_existing_connection()?;
        let order_clause = match request.order {
            SessionOverviewOrder::Asc => "ASC",
            SessionOverviewOrder::Desc => "DESC",
        };
        let limit = request.limit.saturating_add(1) as i64;
        let before_sequence = request.before_sequence.map(|sequence| sequence.0 as i64);
        let after_sequence = request.after_sequence.map(|sequence| sequence.0 as i64);
        let mut items = match (before_sequence, after_sequence) {
            (Some(before), Some(after)) => {
                let sql = overview_page_sql(
                    "AND sequence_no < ?2 AND sequence_no > ?3",
                    order_clause,
                    "?4",
                );
                let mut stmt = conn.prepare(&sql)?;
                let rows =
                    stmt.query(params![request.session_id.0.as_str(), before, after, limit])?;
                collect_overview_items(rows)?
            }
            (Some(before), None) => {
                let sql = overview_page_sql("AND sequence_no < ?2", order_clause, "?3");
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query(params![request.session_id.0.as_str(), before, limit])?;
                collect_overview_items(rows)?
            }
            (None, Some(after)) => {
                let sql = overview_page_sql("AND sequence_no > ?2", order_clause, "?3");
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query(params![request.session_id.0.as_str(), after, limit])?;
                collect_overview_items(rows)?
            }
            (None, None) => {
                let sql = overview_page_sql("", order_clause, "?2");
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query(params![request.session_id.0.as_str(), limit])?;
                collect_overview_items(rows)?
            }
        };

        let has_more = items.len() > request.limit;
        if has_more {
            items.truncate(request.limit);
        }

        Ok(SessionOverviewPage { items, has_more })
    }

    pub fn read_session_check_detail(
        &self,
        session_id: &SessionId,
        sequence_no: CommandSequenceNo,
    ) -> Result<Option<SessionCheckDetail>, SessionStoreError> {
        if !self.database_exists() {
            return Ok(None);
        }

        let conn = self.open_existing_connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT raw_event_json
            FROM events
            WHERE session_id = ?1
              AND kind = 'check'
              AND sequence_no = ?2
            ORDER BY event_index DESC
            LIMIT 1
            "#,
        )?;

        let raw_event_json = stmt
            .query_row(
                params![session_id.0.as_str(), sequence_no.0 as i64],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let Some(raw_event_json) = raw_event_json else {
            return Ok(None);
        };

        let event: SessionEvent =
            serde_json::from_str(&raw_event_json).map_err(SessionStoreError::Decode)?;

        match event.kind {
            SessionEventKind::Check {
                request,
                response,
                state_effect,
            } => Ok(Some(SessionCheckDetail {
                session_id: event.session_id,
                sequence_no: request.sequence_no,
                event_index: event.event_index,
                observed_at_ms: event.observed_at_ms,
                request,
                response,
                state_effect,
            })),
            SessionEventKind::ShellStateDelta { .. } => Ok(None),
        }
    }

    pub fn read_session_list_page(
        &self,
        request: &SessionListPageRequest,
    ) -> Result<SessionListPage, SessionStoreError> {
        if !self.database_exists() {
            return Ok(SessionListPage {
                items: Vec::new(),
                has_more: false,
                next_cursor: None,
            });
        }

        let conn = self.open_existing_connection()?;
        let limit = request.limit.saturating_add(1) as i64;
        let sql = session_list_page_sql(&request);
        let mut stmt = conn.prepare(&sql)?;
        let cursor_time = request
            .cursor
            .as_ref()
            .map(|cursor| cursor.last_observed_at_ms as i64);
        let cursor_session = request
            .cursor
            .as_ref()
            .map(|cursor| cursor.session_id.0.as_str());
        let workspace_root = request.workspace_root.as_deref();
        let rows = stmt.query(params![workspace_root, cursor_time, cursor_session, limit])?;
        let mut items = collect_session_list_items(rows)?;

        let has_more = items.len() > request.limit;
        let next_cursor = if has_more {
            items.truncate(request.limit);
            items.last().map(|item| SessionListCursor {
                last_observed_at_ms: item.last_observed_at_ms,
                session_id: item.session_id.clone(),
            })
        } else {
            None
        };

        Ok(SessionListPage {
            items,
            has_more,
            next_cursor,
        })
    }

    pub fn write_snapshot(&self, snapshot: &SessionSnapshot) -> Result<(), SessionStoreError> {
        let conn = self.open_existing_connection()?;
        self.write_snapshot_with_connection(&conn, snapshot)
    }

    pub fn write_snapshot_with_connection(
        &self,
        conn: &Connection,
        snapshot: &SessionSnapshot,
    ) -> Result<(), SessionStoreError> {
        let snapshot_json = serde_json::to_string(snapshot).map_err(SessionStoreError::Encode)?;
        let updated_at_ms = current_time_ms()? as i64;

        conn.execute(
            r#"
            INSERT INTO snapshots (
                session_id,
                last_event_index,
                snapshot_json,
                updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(session_id) DO UPDATE SET
                last_event_index = excluded.last_event_index,
                snapshot_json = excluded.snapshot_json,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                snapshot.session_id.0.as_str(),
                snapshot.last_event_index as i64,
                snapshot_json,
                updated_at_ms,
            ],
        )?;

        Ok(())
    }

    pub fn read_snapshot(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionSnapshot>, SessionStoreError> {
        if !self.database_exists() {
            return Ok(None);
        }

        let conn = self.open_existing_connection()?;
        let snapshot_json = conn
            .query_row(
                r#"
                SELECT snapshot_json
                FROM snapshots
                WHERE session_id = ?1
                "#,
                params![session_id.0.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        snapshot_json
            .map(|value| serde_json::from_str(&value).map_err(SessionStoreError::Decode))
            .transpose()
    }

    fn database_exists(&self) -> bool {
        self.database_path().is_file()
    }

    fn session_logs_dir(&self) -> PathBuf {
        self.root_dir.join(SESSION_LOGS_DIR_NAME)
    }

    fn session_log_path(&self, session_id: &SessionId) -> PathBuf {
        self.session_logs_dir()
            .join(format!("{}.jsonl", session_log_file_stem(session_id)))
    }

    pub fn compact_log_after_snapshot(
        &self,
        session_id: &SessionId,
        retain_tail_event_count: u64,
    ) -> Result<(), SessionStoreError> {
        let Some(snapshot) = self.read_snapshot(session_id)? else {
            return Ok(());
        };

        self.compact_log_up_to(
            session_id,
            snapshot
                .last_event_index
                .saturating_sub(retain_tail_event_count),
        )
    }

    fn compact_log_up_to(
        &self,
        session_id: &SessionId,
        through_event_index: u64,
    ) -> Result<(), SessionStoreError> {
        if through_event_index == 0 {
            return Ok(());
        }

        let retained_events = self.read_log_events(session_id, through_event_index)?;
        let path = self.session_log_path(session_id);
        let temp_path = path.with_extension("jsonl.compact.tmp");

        {
            let mut temp_file = open_private_truncate(&temp_path)?;
            for event in &retained_events {
                append_event_jsonl(&mut temp_file, event)?;
            }
            temp_file.sync_data()?;
        }

        fs::rename(&temp_path, &path)?;
        Ok(())
    }

    fn read_log_events(
        &self,
        session_id: &SessionId,
        after_event_index: u64,
    ) -> Result<Vec<SessionEvent>, SessionStoreError> {
        let path = self.session_log_path(session_id);
        secure_existing_file(&path)?;
        let Some(file) = open_if_exists(&path)? else {
            return Ok(Vec::new());
        };

        decode_log_file(file, after_event_index)
    }

    fn open_existing_connection(&self) -> Result<Connection, SessionStoreError> {
        self.ensure_private_directories()?;
        self.secure_database_files()?;
        let conn =
            Connection::open_with_flags(self.database_path(), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        ensure_store_schema(&conn)?;
        self.secure_database_files()?;
        Ok(conn)
    }

    fn ensure_private_directories(&self) -> Result<(), SessionStoreError> {
        ensure_private_directory(&self.root_dir)?;
        ensure_private_directory(&self.session_logs_dir())
    }

    fn migrate_existing_log_permissions(&self) -> Result<(), SessionStoreError> {
        for entry in fs::read_dir(self.session_logs_dir())? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                secure_existing_file(&entry.path())?;
            }
        }
        Ok(())
    }

    fn secure_database_files(&self) -> Result<(), SessionStoreError> {
        let database_path = self.database_path();
        secure_existing_file(&database_path)?;
        secure_existing_file(&path_with_suffix(&database_path, "-wal"))?;
        secure_existing_file(&path_with_suffix(&database_path, "-shm"))
    }
}

impl SessionStoreMaterializer {
    pub fn materialize_event(&mut self, event: &SessionEvent) -> Result<(), SessionStoreError> {
        self.store
            .materialize_event_with_connection(&self.conn, event)
    }

    pub fn write_snapshot(&mut self, snapshot: &SessionSnapshot) -> Result<(), SessionStoreError> {
        self.store
            .write_snapshot_with_connection(&self.conn, snapshot)
    }
}

impl SessionLogWriter {
    pub fn append_event(&mut self, event: &SessionEvent) -> Result<(), SessionStoreError> {
        let session_id = event.session_id.clone();
        if !self.files.contains_key(&session_id) {
            self.store.ensure_private_directories()?;
            let file = open_private_append(&self.store.session_log_path(&session_id))?;
            self.files.insert(session_id.clone(), file);
        }

        let file = self
            .files
            .get_mut(&session_id)
            .expect("session log file must exist after insertion");
        append_event_jsonl(file, event)?;

        let unsynced_count = self
            .unsynced_event_counts
            .entry(session_id.clone())
            .or_default();
        *unsynced_count += 1;
        if *unsynced_count >= LOG_SYNC_EVENT_INTERVAL {
            file.sync_data()?;
            *unsynced_count = 0;
        }

        Ok(())
    }

    pub fn sync_all(&mut self) -> Result<(), SessionStoreError> {
        for (session_id, file) in self.files.iter_mut() {
            let unsynced_count = self
                .unsynced_event_counts
                .get(session_id)
                .copied()
                .unwrap_or(0);
            if unsynced_count == 0 {
                continue;
            }

            file.sync_data()?;
            self.unsynced_event_counts.insert(session_id.clone(), 0);
        }

        Ok(())
    }

    pub fn compact_up_to(
        &mut self,
        session_id: &SessionId,
        through_event_index: u64,
    ) -> Result<(), SessionStoreError> {
        if through_event_index == 0 {
            return Ok(());
        }

        let existing_file = if let Some(file) = self.files.get_mut(session_id) {
            file.sync_data()?;
            true
        } else {
            false
        };

        self.store
            .compact_log_up_to(session_id, through_event_index)?;

        let path = self.store.session_log_path(session_id);

        let retained_events = self.store.read_log_events(session_id, 0)?;
        if existing_file || !retained_events.is_empty() {
            let reopened = open_private_append(&path)?;
            self.files.insert(session_id.clone(), reopened);
        }
        self.unsynced_event_counts.insert(session_id.clone(), 0);

        Ok(())
    }
}

fn configure_connection(conn: &Connection) -> Result<(), SessionStoreError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), SessionStoreError> {
    fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(SessionStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("store path is not a real directory: {}", path.display()),
            )));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }

    Ok(())
}

fn ensure_private_file_exists(path: &Path) -> Result<(), SessionStoreError> {
    secure_existing_file(path)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);

    let file = options.open(path)?;
    set_private_file_permissions(&file)
}

fn open_private_append(path: &Path) -> Result<File, SessionStoreError> {
    secure_existing_file(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);

    let file = options.open(path)?;
    set_private_file_permissions(&file)?;
    Ok(file)
}

fn open_private_truncate(path: &Path) -> Result<File, SessionStoreError> {
    secure_existing_file(path)?;
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);

    let file = options.open(path)?;
    set_private_file_permissions(&file)?;
    Ok(file)
}

fn secure_existing_file(path: &Path) -> Result<(), SessionStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(SessionStoreError::Io(error)),
    };

    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SessionStoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("store path is not a regular file: {}", path.display()),
        )));
    }

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;

    Ok(())
}

fn set_private_file_permissions(file: &File) -> Result<(), SessionStoreError> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;

    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn session_log_file_stem(session_id: &SessionId) -> String {
    let mut value = String::with_capacity(session_id.0.len() * 2);
    for byte in session_id.0.as_bytes() {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

fn append_event_jsonl(file: &mut File, event: &SessionEvent) -> Result<(), SessionStoreError> {
    let raw_event_json = serde_json::to_string(event).map_err(SessionStoreError::Encode)?;
    file.write_all(raw_event_json.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn open_if_exists(path: &Path) -> Result<Option<File>, SessionStoreError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SessionStoreError::Io(error)),
    }
}

fn decode_log_file(
    file: File,
    after_event_index: u64,
) -> Result<Vec<SessionEvent>, SessionStoreError> {
    let mut events = Vec::new();
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        let bytes_read = reader.read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let terminated = buffer.ends_with(b"\n");
        if terminated {
            buffer.pop();
            if buffer.ends_with(b"\r") {
                buffer.pop();
            }
        }

        if buffer.is_empty() {
            continue;
        }

        match serde_json::from_slice::<SessionEvent>(&buffer) {
            Ok(event) => {
                if event.event_index > after_event_index {
                    events.push(event);
                }
            }
            Err(_error) if !terminated => break,
            Err(error) => return Err(SessionStoreError::Decode(error)),
        }
    }

    Ok(events)
}

fn overview_page_sql(sequence_filter: &str, order_clause: &str, limit_parameter: &str) -> String {
    format!(
        r#"
        SELECT
            event_index,
            observed_at_ms,
            sequence_no,
            command,
            decision,
            finding_count,
            evidence_count,
            has_derived_invocations,
            has_nested_payloads,
            has_execution_payload_sink,
            has_startup_config_load,
            has_interactive_escape
        FROM events
        WHERE session_id = ?1
          AND kind = 'check'
          {sequence_filter}
        ORDER BY sequence_no {order_clause}
        LIMIT {limit_parameter}
        "#
    )
}

fn collect_overview_items(
    mut rows: rusqlite::Rows<'_>,
) -> Result<Vec<SessionOverviewItem>, SessionStoreError> {
    let mut items = Vec::new();

    while let Some(row) = rows.next()? {
        items.push(overview_item_from_row(row)?);
    }

    Ok(items)
}

fn overview_item_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<SessionOverviewItem, SessionStoreError> {
    let decision: String = row.get(4)?;

    Ok(SessionOverviewItem {
        event_index: row.get::<_, i64>(0)? as u64,
        observed_at_ms: row.get::<_, i64>(1)? as u64,
        sequence_no: CommandSequenceNo::new(row.get::<_, i64>(2)? as u64),
        raw_text: row.get(3)?,
        decision: decision_from_str(&decision)?,
        finding_count: row.get::<_, i64>(5)? as usize,
        evidence_count: row.get::<_, i64>(6)? as usize,
        has_derived_invocations: row.get::<_, i64>(7)? != 0,
        has_nested_payloads: row.get::<_, i64>(8)? != 0,
        has_execution_payload_sink: row.get::<_, i64>(9)? != 0,
        has_startup_config_load: row.get::<_, i64>(10)? != 0,
        has_interactive_escape: row.get::<_, i64>(11)? != 0,
    })
}

fn session_list_page_sql(request: &SessionListPageRequest) -> String {
    let latest_check_filter = match request.scope {
        SessionListScope::CurrentWorkspace => "AND (?1 IS NOT NULL AND workspace_root = ?1)",
        SessionListScope::All => "",
    };

    let cursor_filter = match request.order {
        SessionOverviewOrder::Desc => {
            "AND (
                ?2 IS NULL
                OR rollup.last_observed_at_ms < ?2
                OR (rollup.last_observed_at_ms = ?2 AND rollup.session_id < ?3)
            )"
        }
        SessionOverviewOrder::Asc => {
            "AND (
                ?2 IS NULL
                OR rollup.last_observed_at_ms > ?2
                OR (rollup.last_observed_at_ms = ?2 AND rollup.session_id > ?3)
            )"
        }
    };
    let order_clause = match request.order {
        SessionOverviewOrder::Asc => "ASC",
        SessionOverviewOrder::Desc => "DESC",
    };

    format!(
        r#"
        WITH session_rollup AS (
            SELECT
                session_id,
                MIN(observed_at_ms) AS first_observed_at_ms,
                MAX(observed_at_ms) AS last_observed_at_ms,
                MAX(event_index) AS last_event_index,
                COUNT(*) AS event_count,
                SUM(CASE WHEN kind = 'check' THEN 1 ELSE 0 END) AS check_count
            FROM events
            GROUP BY session_id
        ),
        latest_check AS (
            SELECT
                session_id,
                sequence_no,
                command,
                decision,
                workspace_root,
                runtime_name,
                observed_at_ms,
                ROW_NUMBER() OVER (
                    PARTITION BY session_id
                    ORDER BY sequence_no DESC, event_index DESC
                ) AS rank
            FROM events
            WHERE kind = 'check'
            {latest_check_filter}
        )
        SELECT
            rollup.session_id,
            rollup.first_observed_at_ms,
            rollup.last_observed_at_ms,
            rollup.last_event_index,
            rollup.event_count,
            rollup.check_count,
            latest.sequence_no,
            latest.command,
            latest.decision,
            latest.workspace_root,
            latest.runtime_name
        FROM session_rollup rollup
        JOIN latest_check latest
          ON latest.session_id = rollup.session_id
         AND latest.rank = 1
        WHERE 1 = 1
          {cursor_filter}
        ORDER BY rollup.last_observed_at_ms {order_clause}, rollup.session_id {order_clause}
        LIMIT ?4
        "#
    )
}

fn collect_session_list_items(
    mut rows: rusqlite::Rows<'_>,
) -> Result<Vec<SessionListItem>, SessionStoreError> {
    let mut items = Vec::new();

    while let Some(row) = rows.next()? {
        items.push(session_list_item_from_row(row)?);
    }

    Ok(items)
}

fn session_list_item_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<SessionListItem, SessionStoreError> {
    let decision: Option<String> = row.get(8)?;

    Ok(SessionListItem {
        session_id: SessionId::new(row.get::<_, String>(0)?),
        first_observed_at_ms: row.get::<_, i64>(1)? as u64,
        last_observed_at_ms: row.get::<_, i64>(2)? as u64,
        last_event_index: row.get::<_, i64>(3)? as u64,
        event_count: row.get::<_, i64>(4)? as usize,
        check_count: row.get::<_, i64>(5)? as usize,
        last_sequence_no: row
            .get::<_, Option<i64>>(6)?
            .map(|sequence| CommandSequenceNo::new(sequence as u64)),
        last_command: row.get(7)?,
        last_decision: decision.as_deref().map(decision_from_str).transpose()?,
        workspace_root: row.get(9)?,
        runtime_name: row.get(10)?,
    })
}

fn ensure_store_schema(conn: &Connection) -> Result<(), SessionStoreError> {
    ensure_event_column(conn, "workspace_root", "TEXT")?;
    ensure_event_column(conn, "runtime_name", "TEXT")?;
    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS events_session_workspace_idx
        ON events(kind, workspace_root, observed_at_ms, session_id);
        "#,
    )?;

    backfill_event_metadata(conn)
}

fn ensure_event_column(
    conn: &Connection,
    column_name: &str,
    column_type: &str,
) -> Result<(), SessionStoreError> {
    let mut stmt = conn.prepare("PRAGMA table_info(events)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let existing_name: String = row.get(1)?;
        if existing_name == column_name {
            return Ok(());
        }
    }
    drop(rows);
    drop(stmt);

    conn.execute(
        &format!("ALTER TABLE events ADD COLUMN {column_name} {column_type}"),
        [],
    )?;
    Ok(())
}

fn backfill_event_metadata(conn: &Connection) -> Result<(), SessionStoreError> {
    let mut stmt = conn.prepare(
        r#"
        SELECT session_id, event_index, raw_event_json
        FROM events
        WHERE kind = 'check'
          AND (workspace_root IS NULL OR runtime_name IS NULL)
        ORDER BY session_id, event_index
        "#,
    )?;
    let mut rows = stmt.query([])?;
    let mut updates = Vec::new();

    while let Some(row) = rows.next()? {
        let raw_event_json: String = row.get(2)?;
        let event: SessionEvent =
            serde_json::from_str(&raw_event_json).map_err(SessionStoreError::Decode)?;
        let projection = EventProjection::from_event(&event);
        updates.push((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            projection.workspace_root,
            projection.runtime_name,
        ));
    }
    drop(rows);
    drop(stmt);

    if updates.is_empty() {
        return Ok(());
    }

    let mut update_stmt = conn.prepare(
        r#"
        UPDATE events
        SET workspace_root = ?3,
            runtime_name = ?4
        WHERE session_id = ?1
          AND event_index = ?2
        "#,
    )?;

    for (session_id, event_index, workspace_root, runtime_name) in updates {
        update_stmt.execute(params![
            session_id,
            event_index,
            workspace_root,
            runtime_name
        ])?;
    }

    Ok(())
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn decision_to_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::NeedApproval => "need_approval",
        Decision::Deny => "deny",
    }
}

fn decision_from_str(value: &str) -> Result<Decision, SessionStoreError> {
    match value {
        "allow" => Ok(Decision::Allow),
        "need_approval" => Ok(Decision::NeedApproval),
        "deny" => Ok(Decision::Deny),
        other => Err(SessionStoreError::InvalidDecision(other.to_string())),
    }
}

fn current_time_ms() -> Result<u64, SessionStoreError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(SessionStoreError::Clock)?
        .as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::{SessionListPageRequest, SessionOverviewPageRequest, SessionStore};
    use caushell_types::{
        CheckRequest, CheckResponse, CommandSequenceNo, Decision, DecisionTrace, RuntimeMetadata,
        RuntimeShellStateDeltaRequest, SessionEvent, SessionGraphSnapshot, SessionId,
        SessionListCursor, SessionListScope, SessionOverviewOrder, SessionSnapshot,
        SessionStateEffect, SessionSummary, ShellKind, ShellStateDelta, ShellStateSnapshot,
    };
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store_root(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("expected wall clock after unix epoch")
            .as_nanos();

        std::env::temp_dir().join(format!("caushell-store-{name}-{unique}"))
    }

    fn initialized_store(root: &Path) -> SessionStore {
        let store = SessionStore::new(root);
        store
            .initialize_database()
            .expect("expected store bootstrap to succeed");
        store
    }

    fn sample_request(session_id: &str, sequence_no: u64, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new(session_id),
            sequence_no: CommandSequenceNo::new(sequence_no),
            command: command.to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn sample_runtime_metadata() -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_name: "claude_code".to_string(),
            tool_name: Some("Bash".to_string()),
            shell_runtime_capabilities: caushell_types::ShellRuntimeCapabilities::persistent_shell(
            ),
        }
    }

    fn sample_response(decision: Decision) -> CheckResponse {
        CheckResponse {
            decision,
            reasons: vec![],
            decision_trace: DecisionTrace::default(),
        }
    }

    fn sample_state_effect(sequence_no: u64) -> SessionStateEffect {
        SessionStateEffect::observe_only(CommandSequenceNo::new(sequence_no))
    }

    #[cfg(unix)]
    #[test]
    fn initialize_database_hardens_existing_and_new_store_permissions() {
        let root = temp_store_root("private-permissions");
        let logs_dir = root.join("session-logs");
        let database_path = root.join("caushell.sqlite3");
        let legacy_log_path = logs_dir.join("legacy.jsonl");

        fs::create_dir_all(&logs_dir).expect("expected legacy store directories to be created");
        fs::write(&database_path, []).expect("expected legacy database file to be created");
        fs::write(&legacy_log_path, b"legacy\n")
            .expect("expected legacy session log to be created");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("expected legacy root mode to be set");
        fs::set_permissions(&logs_dir, fs::Permissions::from_mode(0o755))
            .expect("expected legacy log directory mode to be set");
        fs::set_permissions(&database_path, fs::Permissions::from_mode(0o644))
            .expect("expected legacy database mode to be set");
        fs::set_permissions(&legacy_log_path, fs::Permissions::from_mode(0o644))
            .expect("expected legacy log mode to be set");

        let store = initialized_store(&root);
        let event = SessionEvent::new_check(
            SessionId::new("sess-private"),
            1,
            1_000,
            sample_request("sess-private", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        store
            .append_event(&event)
            .expect("expected private event append to succeed");

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&logs_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&database_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&legacy_log_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(store.session_log_path(&event.session_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        for suffix in ["-wal", "-shm"] {
            let path = super::path_with_suffix(&database_path, suffix);
            if path.exists() {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn append_event_and_read_events_roundtrip() {
        let root = temp_store_root("events");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            2,
            2_000,
            sample_request("sess-1", 2, "ls"),
            sample_response(Decision::NeedApproval),
            sample_state_effect(2),
        );

        store
            .append_event(&first)
            .expect("expected first event append to succeed");
        store
            .append_event(&second)
            .expect("expected second event append to succeed");

        let events = store
            .read_events(&session_id)
            .expect("expected stored events to be readable");

        assert_eq!(events, vec![first, second]);
        assert!(store.database_path().exists());

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_events_returns_empty_when_session_has_no_log() {
        let root = temp_store_root("missing-events");
        let store = SessionStore::new(&root);

        let events = store
            .read_events(&SessionId::new("sess-missing"))
            .expect("expected missing event log to read as empty");

        assert!(events.is_empty());
        assert!(!store.database_path().exists());

        if root.exists() {
            fs::remove_dir_all(root).expect("expected temp store root to be removed");
        }
    }

    #[test]
    fn read_queries_on_empty_store_do_not_bootstrap_database() {
        let root = temp_store_root("empty-read-no-bootstrap");
        let store = SessionStore::new(&root);

        let overview = store
            .read_session_overview_page(&SessionOverviewPageRequest {
                session_id: SessionId::new("sess-missing"),
                limit: 10,
                before_sequence: None,
                after_sequence: None,
                order: SessionOverviewOrder::Desc,
            })
            .expect("expected overview read to succeed");
        let list = store
            .read_session_list_page(&SessionListPageRequest {
                limit: 10,
                cursor: None,
                workspace_root: None,
                scope: SessionListScope::All,
                order: SessionOverviewOrder::Desc,
            })
            .expect("expected session list read to succeed");
        let detail = store
            .read_session_check_detail(&SessionId::new("sess-missing"), CommandSequenceNo::new(1))
            .expect("expected detail read to succeed");
        let snapshot = store
            .read_snapshot(&SessionId::new("sess-missing"))
            .expect("expected snapshot read to succeed");

        assert!(overview.items.is_empty());
        assert!(!overview.has_more);
        assert!(list.items.is_empty());
        assert!(!list.has_more);
        assert!(detail.is_none());
        assert!(snapshot.is_none());
        assert!(!store.database_path().exists());

        if root.exists() {
            fs::remove_dir_all(root).expect("expected temp store root to be removed");
        }
    }

    #[test]
    fn read_events_after_returns_tail_only() {
        let root = temp_store_root("events-after");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            2,
            2_000,
            sample_request("sess-1", 2, "ls"),
            sample_response(Decision::Allow),
            sample_state_effect(2),
        );

        store
            .append_event(&first)
            .expect("expected first event append to succeed");
        store
            .append_event(&second)
            .expect("expected second event append to succeed");

        let events = store
            .read_events_after(&session_id, 1)
            .expect("expected event tail to be readable");

        assert_eq!(events, vec![second]);

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_events_ignores_truncated_tail_record() {
        let root = temp_store_root("events-truncated-tail");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            2,
            2_000,
            sample_request("sess-1", 2, "ls"),
            sample_response(Decision::Allow),
            sample_state_effect(2),
        );

        store
            .append_event(&first)
            .expect("expected first event append to succeed");
        store
            .append_event(&second)
            .expect("expected second event append to succeed");

        let mut file = OpenOptions::new()
            .append(true)
            .open(store.session_log_path(&session_id))
            .expect("expected session log file to be openable");
        file.write_all(br#"{"session_id":"sess-1","event_index":3"#)
            .expect("expected truncated tail to be appended");

        let events = store
            .read_events(&session_id)
            .expect("expected readable events despite truncated tail");

        assert_eq!(events, vec![first, second]);

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_events_still_works_when_materialized_database_is_missing() {
        let root = temp_store_root("events-without-database");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            2,
            2_000,
            sample_request("sess-1", 2, "ls"),
            sample_response(Decision::Allow),
            sample_state_effect(2),
        );

        store
            .append_event(&first)
            .expect("expected first event append to succeed");
        store
            .append_event(&second)
            .expect("expected second event append to succeed");

        fs::remove_file(store.database_path())
            .expect("expected materialized database file to be removable");

        let events = store
            .read_events(&session_id)
            .expect("expected log-backed event read without database");

        assert_eq!(events, vec![first, second]);

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_session_overview_page_descending_returns_latest_matching_checks_only() {
        let root = temp_store_root("overview-page-desc");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let delta = SessionEvent::new_shell_state_delta(
            session_id.clone(),
            2,
            1_500,
            RuntimeShellStateDeltaRequest {
                session_id: session_id.clone(),
                sequence_no: CommandSequenceNo::new(1),
                runtime: sample_runtime_metadata(),
                delta: ShellStateDelta::new().with_cwd_after("/tmp/project/subdir"),
            },
            Vec::new(),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            3,
            2_000,
            sample_request("sess-1", 2, "ls"),
            sample_response(Decision::Allow),
            sample_state_effect(2),
        );
        let third = SessionEvent::new_check(
            session_id.clone(),
            4,
            3_000,
            sample_request("sess-1", 3, "bash -c 'echo ok'"),
            sample_response(Decision::NeedApproval),
            sample_state_effect(3),
        );

        for event in [&first, &delta, &second, &third] {
            store
                .append_event(event)
                .expect("expected session event append to succeed");
        }

        let page = store
            .read_session_overview_page(&SessionOverviewPageRequest {
                session_id: session_id.clone(),
                limit: 2,
                before_sequence: None,
                after_sequence: None,
                order: SessionOverviewOrder::Desc,
            })
            .expect("expected descending overview page to be readable");

        assert!(page.has_more);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].sequence_no, CommandSequenceNo::new(3));
        assert_eq!(page.items[0].raw_text, "bash -c 'echo ok'");
        assert_eq!(page.items[0].decision, Decision::NeedApproval);
        assert_eq!(page.items[1].sequence_no, CommandSequenceNo::new(2));
        assert_eq!(page.items[1].raw_text, "ls");

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_session_overview_page_ascending_honors_after_and_before_sequence() {
        let root = temp_store_root("overview-page-asc");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            2,
            2_000,
            sample_request("sess-1", 2, "ls"),
            sample_response(Decision::Allow),
            sample_state_effect(2),
        );
        let third = SessionEvent::new_check(
            session_id.clone(),
            3,
            3_000,
            sample_request("sess-1", 3, "cat ./payload.sh | bash"),
            sample_response(Decision::NeedApproval),
            sample_state_effect(3),
        );
        let fourth = SessionEvent::new_check(
            session_id.clone(),
            4,
            4_000,
            sample_request("sess-1", 4, "less README.md"),
            sample_response(Decision::Allow),
            sample_state_effect(4),
        );

        for event in [&first, &second, &third, &fourth] {
            store
                .append_event(event)
                .expect("expected session event append to succeed");
        }

        let page = store
            .read_session_overview_page(&SessionOverviewPageRequest {
                session_id: session_id.clone(),
                limit: 2,
                before_sequence: Some(CommandSequenceNo::new(4)),
                after_sequence: Some(CommandSequenceNo::new(1)),
                order: SessionOverviewOrder::Asc,
            })
            .expect("expected ascending overview page to be readable");

        assert!(!page.has_more);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].sequence_no, CommandSequenceNo::new(2));
        assert_eq!(page.items[0].raw_text, "ls");
        assert_eq!(page.items[1].sequence_no, CommandSequenceNo::new(3));
        assert_eq!(page.items[1].raw_text, "cat ./payload.sh | bash");

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_session_check_detail_returns_targeted_check_event() {
        let root = temp_store_root("session-check-detail");
        let store = initialized_store(&root);
        let session_id = SessionId::new("sess-1");
        let first = SessionEvent::new_check(
            session_id.clone(),
            1,
            1_000,
            sample_request("sess-1", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let delta = SessionEvent::new_shell_state_delta(
            session_id.clone(),
            2,
            1_500,
            RuntimeShellStateDeltaRequest {
                session_id: session_id.clone(),
                sequence_no: CommandSequenceNo::new(1),
                runtime: sample_runtime_metadata(),
                delta: ShellStateDelta::new().with_cwd_after("/tmp/project/subdir"),
            },
            Vec::new(),
        );
        let second = SessionEvent::new_check(
            session_id.clone(),
            3,
            2_000,
            sample_request("sess-1", 2, "bash -c 'echo ok'"),
            sample_response(Decision::NeedApproval),
            sample_state_effect(2),
        );

        for event in [&first, &delta, &second] {
            store
                .append_event(event)
                .expect("expected session event append to succeed");
        }

        let detail = store
            .read_session_check_detail(&session_id, CommandSequenceNo::new(2))
            .expect("expected targeted check detail to be readable")
            .expect("expected check detail to exist");

        assert_eq!(detail.sequence_no, CommandSequenceNo::new(2));
        assert_eq!(detail.event_index, 3);
        assert_eq!(detail.request.command, "bash -c 'echo ok'");
        assert_eq!(detail.response.decision, Decision::NeedApproval);

        let missing = store
            .read_session_check_detail(&session_id, CommandSequenceNo::new(99))
            .expect("expected missing detail lookup to succeed");
        assert!(missing.is_none());

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_session_list_page_returns_latest_session_summaries() {
        let root = temp_store_root("session-list");
        let store = initialized_store(&root);
        let sess_1 = SessionId::new("sess-1");
        let sess_2 = SessionId::new("sess-2");

        let events = [
            SessionEvent::new_check(
                sess_1.clone(),
                1,
                1_000,
                sample_request("sess-1", 1, "pwd"),
                sample_response(Decision::Allow),
                sample_state_effect(1),
            ),
            SessionEvent::new_check(
                sess_2.clone(),
                1,
                2_000,
                sample_request("sess-2", 1, "ls"),
                sample_response(Decision::Allow),
                sample_state_effect(1),
            ),
            SessionEvent::new_shell_state_delta(
                sess_1.clone(),
                2,
                2_500,
                RuntimeShellStateDeltaRequest {
                    session_id: sess_1.clone(),
                    sequence_no: CommandSequenceNo::new(1),
                    runtime: sample_runtime_metadata(),
                    delta: ShellStateDelta::new().with_cwd_after("/tmp/project/subdir"),
                },
                Vec::new(),
            ),
            SessionEvent::new_check(
                sess_1.clone(),
                3,
                3_000,
                sample_request("sess-1", 2, "curl https://example.test/payload.sh | bash"),
                sample_response(Decision::NeedApproval),
                sample_state_effect(2),
            ),
        ];

        for event in &events {
            store
                .append_event(event)
                .expect("expected session event append to succeed");
        }

        let page = store
            .read_session_list_page(&SessionListPageRequest {
                limit: 10,
                cursor: None,
                workspace_root: None,
                scope: SessionListScope::All,
                order: SessionOverviewOrder::Desc,
            })
            .expect("expected session list page to be readable");

        assert!(!page.has_more);
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.items.len(), 2);

        let latest = &page.items[0];
        assert_eq!(latest.session_id, sess_1);
        assert_eq!(latest.first_observed_at_ms, 1_000);
        assert_eq!(latest.last_observed_at_ms, 3_000);
        assert_eq!(latest.last_event_index, 3);
        assert_eq!(latest.event_count, 3);
        assert_eq!(latest.check_count, 2);
        assert_eq!(latest.last_sequence_no, Some(CommandSequenceNo::new(2)));
        assert_eq!(
            latest.last_command.as_deref(),
            Some("curl https://example.test/payload.sh | bash")
        );
        assert_eq!(latest.last_decision, Some(Decision::NeedApproval));

        let older = &page.items[1];
        assert_eq!(older.session_id, sess_2);
        assert_eq!(older.first_observed_at_ms, 2_000);
        assert_eq!(older.last_observed_at_ms, 2_000);
        assert_eq!(older.last_event_index, 1);
        assert_eq!(older.event_count, 1);
        assert_eq!(older.check_count, 1);
        assert_eq!(older.last_sequence_no, Some(CommandSequenceNo::new(1)));
        assert_eq!(older.last_command.as_deref(), Some("ls"));
        assert_eq!(older.last_decision, Some(Decision::Allow));

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_session_list_page_honors_cursor_and_order() {
        let root = temp_store_root("session-list-cursor-pagination");
        let store = initialized_store(&root);

        for (session_id, observed_at_ms) in [
            ("sess-a", 1_000_u64),
            ("sess-b", 2_000_u64),
            ("sess-c", 3_000_u64),
        ] {
            let event = SessionEvent::new_check(
                SessionId::new(session_id),
                1,
                observed_at_ms,
                sample_request(session_id, 1, "pwd"),
                sample_response(Decision::Allow),
                sample_state_effect(1),
            );
            store
                .append_event(&event)
                .expect("expected session event append to succeed");
        }

        let page = store
            .read_session_list_page(&SessionListPageRequest {
                limit: 1,
                cursor: Some(SessionListCursor {
                    last_observed_at_ms: 1_000,
                    session_id: SessionId::new("sess-a"),
                }),
                workspace_root: None,
                scope: SessionListScope::All,
                order: SessionOverviewOrder::Asc,
            })
            .expect("expected session list page to be readable");

        assert!(page.has_more);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].session_id, SessionId::new("sess-b"));
        assert_eq!(
            page.next_cursor,
            Some(SessionListCursor {
                last_observed_at_ms: 2_000,
                session_id: SessionId::new("sess-b"),
            })
        );

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_session_list_page_filters_current_workspace_and_returns_metadata() {
        let root = temp_store_root("session-list-workspace-filter");
        let store = initialized_store(&root);

        let workspace_a = SessionEvent::new_check(
            SessionId::new("sess-a"),
            1,
            1_000,
            sample_request("sess-a", 1, "pwd"),
            sample_response(Decision::Allow),
            sample_state_effect(1),
        );
        let mut other_request = sample_request("sess-b", 1, "ls");
        other_request.workspace_root = Some("/tmp/other".to_string());
        other_request.runtime.runtime_name = "codex".to_string();
        let workspace_b = SessionEvent::new_check(
            SessionId::new("sess-b"),
            1,
            2_000,
            other_request,
            sample_response(Decision::NeedApproval),
            sample_state_effect(1),
        );

        for event in [&workspace_a, &workspace_b] {
            store
                .append_event(event)
                .expect("expected session event append to succeed");
        }

        let page = store
            .read_session_list_page(&SessionListPageRequest {
                limit: 10,
                cursor: None,
                workspace_root: Some("/tmp/project".to_string()),
                scope: SessionListScope::CurrentWorkspace,
                order: SessionOverviewOrder::Desc,
            })
            .expect("expected workspace-filtered session list to be readable");

        assert!(!page.has_more);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].session_id, SessionId::new("sess-a"));
        assert_eq!(
            page.items[0].workspace_root.as_deref(),
            Some("/tmp/project")
        );
        assert_eq!(page.items[0].runtime_name.as_deref(), Some("claude_code"));

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn write_snapshot_and_read_snapshot_roundtrip() {
        let root = temp_store_root("snapshot");
        let store = initialized_store(&root);
        let snapshot = SessionSnapshot::new(
            SessionId::new("sess-1"),
            9,
            SessionSummary::default(),
            SessionGraphSnapshot::default(),
        );

        store
            .write_snapshot(&snapshot)
            .expect("expected snapshot write to succeed");

        let restored = store
            .read_snapshot(&SessionId::new("sess-1"))
            .expect("expected snapshot read to succeed");

        assert_eq!(restored, Some(snapshot));
        assert!(store.database_path().exists());

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn write_snapshot_replaces_existing_snapshot() {
        let root = temp_store_root("snapshot-replace");
        let store = initialized_store(&root);
        let first = SessionSnapshot::new(
            SessionId::new("sess-1"),
            1,
            SessionSummary::default(),
            SessionGraphSnapshot::default(),
        );
        let second = SessionSnapshot::new(
            SessionId::new("sess-1"),
            2,
            SessionSummary::default(),
            SessionGraphSnapshot::default(),
        );

        store
            .write_snapshot(&first)
            .expect("expected first snapshot write to succeed");
        store
            .write_snapshot(&second)
            .expect("expected second snapshot write to succeed");

        let restored = store
            .read_snapshot(&SessionId::new("sess-1"))
            .expect("expected snapshot read to succeed")
            .expect("expected snapshot to exist");

        assert_eq!(restored, second);
        assert!(store.database_path().exists());

        fs::remove_dir_all(root).expect("expected temp store root to be removed");
    }

    #[test]
    fn read_snapshot_returns_none_when_missing() {
        let root = temp_store_root("missing-snapshot");
        let store = SessionStore::new(&root);

        let snapshot = store
            .read_snapshot(&SessionId::new("sess-missing"))
            .expect("expected missing snapshot to read as none");

        assert_eq!(snapshot, None);

        if root.exists() {
            fs::remove_dir_all(root).expect("expected temp store root to be removed");
        }
    }
}
