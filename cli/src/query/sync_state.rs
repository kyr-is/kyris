// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

pub struct SyncMetadata {
    pub scope_patterns: Vec<String>,
    pub last_synced_at: Option<String>,
}

pub fn load_sync_metadata(db: &duckdb::Connection) -> Option<SyncMetadata> {
    let row = db
        .query_row(
            "SELECT scope_json, last_synced_at FROM gw.sync_metadata WHERE id = 1",
            [],
            |row| {
                let scope_json: String = row.get(0)?;
                let last_synced_at: Option<String> = row.get(1)?;
                Ok((scope_json, last_synced_at))
            },
        )
        .ok()?;

    let scope_patterns: Vec<String> = serde_json::from_str(&row.0).unwrap_or_default();
    if scope_patterns.is_empty() {
        return None;
    }

    Some(SyncMetadata {
        scope_patterns,
        last_synced_at: row.1,
    })
}

pub fn build_event_sync_expr(meta: Option<&SyncMetadata>) -> String {
    let Some(meta) = meta else {
        return "NULL".to_string();
    };

    let home = std::env::var("HOME").unwrap_or_default();
    let like_clauses: Vec<String> = meta
        .scope_patterns
        .iter()
        .map(|p| {
            let expanded = if let Some(rest) = p.strip_prefix('~') {
                format!("{home}{rest}")
            } else {
                p.clone()
            };
            let safe = expanded.replace('\'', "''");
            if let Some(prefix) = safe.strip_suffix('*') {
                format!("e.working_dir LIKE '{prefix}%'")
            } else {
                format!("(e.working_dir = '{safe}' OR e.working_dir LIKE '{safe}/%')")
            }
        })
        .collect();

    let scope_condition = like_clauses.join(" OR ");

    match &meta.last_synced_at {
        Some(ts) => {
            let safe_ts = ts.replace('\'', "''");
            format!(
                "CASE \
                   WHEN e.working_dir IS NULL THEN NULL \
                   WHEN NOT ({scope_condition}) THEN 'local' \
                   WHEN e.timestamp <= '{safe_ts}' THEN 'synced' \
                   ELSE 'pending' \
                 END"
            )
        }
        None => {
            format!(
                "CASE \
                   WHEN e.working_dir IS NULL THEN NULL \
                   WHEN ({scope_condition}) THEN 'pending' \
                   ELSE 'local' \
                 END"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testBuildEventSyncExprNoMetadata() {
        assert_eq!(build_event_sync_expr(None), "NULL");
    }

    #[test]
    fn testBuildEventSyncExprWithTimestamp() {
        let meta = SyncMetadata {
            scope_patterns: vec!["/work/*".to_string()],
            last_synced_at: Some("2026-04-29T00:00:00Z".to_string()),
        };
        let expr = build_event_sync_expr(Some(&meta));
        assert!(expr.contains("'synced'"), "{expr}");
        assert!(expr.contains("'pending'"), "{expr}");
        assert!(expr.contains("'local'"), "{expr}");
        assert!(expr.contains("/work/%"), "{expr}");
        assert!(expr.contains("2026-04-29"), "{expr}");
    }

    #[test]
    fn testBuildEventSyncExprNoTimestamp() {
        let meta = SyncMetadata {
            scope_patterns: vec!["/work/*".to_string()],
            last_synced_at: None,
        };
        let expr = build_event_sync_expr(Some(&meta));
        assert!(expr.contains("'pending'"), "{expr}");
        assert!(expr.contains("'local'"), "{expr}");
        assert!(!expr.contains("'synced'"), "{expr}");
    }

    #[test]
    fn testBuildEventSyncExprMultiplePatterns() {
        let meta = SyncMetadata {
            scope_patterns: vec!["/work/*".to_string(), "/corp/*".to_string()],
            last_synced_at: Some("2026-04-29T00:00:00Z".to_string()),
        };
        let expr = build_event_sync_expr(Some(&meta));
        assert!(expr.contains("/work/%"), "{expr}");
        assert!(expr.contains("/corp/%"), "{expr}");
        assert!(expr.contains(" OR "), "{expr}");
    }

    #[test]
    fn testBuildEventSyncExprTildeExpansion() {
        let home = std::env::var("HOME").unwrap_or_default();
        let meta = SyncMetadata {
            scope_patterns: vec!["~/projects/*".to_string()],
            last_synced_at: Some("2026-04-29T00:00:00Z".to_string()),
        };
        let expr = build_event_sync_expr(Some(&meta));
        let expected = format!("{home}/projects/%");
        assert!(expr.contains(&expected), "{expr}");
    }

    #[test]
    fn testBuildEventSyncExprExactPattern() {
        let meta = SyncMetadata {
            scope_patterns: vec!["/work/project1".to_string()],
            last_synced_at: Some("2026-04-29T00:00:00Z".to_string()),
        };
        let expr = build_event_sync_expr(Some(&meta));
        assert!(expr.contains("e.working_dir = '/work/project1'"), "{expr}");
        assert!(
            expr.contains("e.working_dir LIKE '/work/project1/%'"),
            "{expr}"
        );
        assert!(
            !expr.contains("e.working_dir LIKE '/work/project1%'"),
            "{expr}"
        );
    }
}
