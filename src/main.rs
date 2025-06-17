
use notify::{Watcher, RecommendedWatcher, RecursiveMode, Config, EventKind};
use std::sync::mpsc::channel;
use std::time::Duration;
use std::path::PathBuf;
use std::fs;
use chrono::NaiveDateTime;
use sqlx::{SqlitePool, Sqlite, query_scalar, query};

static DATABASE_URL: &str = "sqlite://vigil.db";

fn get_last_modified(path: &PathBuf) -> Option<NaiveDateTime> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    Some(NaiveDateTime::from_timestamp(
        modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64,
        0,
    ))
}

#[tokio::main]
async fn main() -> notify::Result<()> {
    let watch_path = "/home/pdc/Downloads"; // caminho da pasta raiz a ser vigiada
    let db_url = "sqlite://vigil.db";
    let pool = SqlitePool::connect(db_url).await.expect("failed to connect to db");

    // cria tabela se nao existir
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS arquivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caminho TEXT UNIQUE NOT NULL,
            last_modified DATETIME NOT NULL,
            sincronizar TEXT CHECK(sincronizar IN ('Sim', 'Nao')) NOT NULL
        )"
    ).execute(&pool).await.unwrap();

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(watch_path, RecursiveMode::Recursive)?;

    println!("🟢 Observando mudanças em: {}", watch_path);

    while let Ok(event) = rx.recv() {
        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            for path in event.paths {
                if path.extension().map(|ext| ext.eq_ignore_ascii_case("jpg")).unwrap_or(false) {
                    if let Some(modified) = get_last_modified(&path) {
                        let path_str = path.to_string_lossy().to_string();

                        let existing = query_scalar!(
                            "SELECT last_modified FROM arquivos WHERE caminho = ?",
                            path_str
                        )
                        .fetch_optional(&pool)
                        .await
                        .unwrap();

                        match existing {
                            Some(last_mod) => {
                                if modified > last_mod {
                                    query!(
                                        "UPDATE arquivos SET sincronizar = 'Sim', last_modified = ? WHERE caminho = ?",
                                        modified,
                                        path_str
                                    )
                                    .execute(&pool)
                                    .await
                                    .unwrap();
                                    println!("🔁 Atualizado: {}", path_str);
                                }
                            }
                            None => {
                                query!(
                                    "INSERT INTO arquivos (caminho, last_modified, sincronizar) VALUES (?, ?, 'Sim')",
                                    path_str,
                                    modified
                                )
                                .execute(&pool)
                                .await
                                .unwrap();
                                println!("➕ Inserido novo: {}", path_str);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

