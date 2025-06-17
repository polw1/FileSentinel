
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::env;
use std::sync::mpsc::channel;
use std::fs;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{query, query_scalar, SqlitePool};

const DATABASE_URL: &str = "sqlite://vigil.db";

fn get_last_modified(path: &PathBuf) -> Option<NaiveDateTime> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    DateTime::<Utc>::from_timestamp(secs, 0).map(|dt| dt.naive_utc())
}

#[tokio::main]
async fn main() -> notify::Result<()> {
    let watch_path = env::args().nth(1).unwrap_or_else(|| "/home/pdc/Downloads".to_string()); // caminho da pasta raiz a ser vigiada
    let pool = SqlitePool::connect(DATABASE_URL).await.expect("failed to connect to db");

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
    let mut watcher = RecommendedWatcher::new(move |res| {
        tx.send(res).unwrap();
    }, Config::default())?;
    watcher.watch(Path::new(&watch_path), RecursiveMode::Recursive)?;

    println!("🟢 Observando mudanças em: {}", watch_path);

    while let Ok(Ok(event)) = rx.recv() {
        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            for path in event.paths {
                if path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        let ext = ext.to_ascii_lowercase();
                        ext == "jpg" || ext == "jpeg"
                    })
                    .unwrap_or(false)
                {
                    if let Some(modified) = get_last_modified(&path) {
                        let path_str = path.to_string_lossy().to_string();

                        let existing: Option<NaiveDateTime> = query_scalar(
                            "SELECT last_modified FROM arquivos WHERE caminho = ?",
                        )
                        .bind(&path_str)
                        .fetch_optional(&pool)
                        .await
                        .unwrap();

                        match existing {
                            Some(last_mod) => {
                                if modified > last_mod {
                                    query(
                                        "UPDATE arquivos SET sincronizar = 'Sim', last_modified = ? WHERE caminho = ?",
                                    )
                                    .bind(modified)
                                    .bind(&path_str)
                                    .execute(&pool)
                                    .await
                                    .unwrap();
                                    println!("🔁 Atualizado: {}", path_str);
                                }
                            }
                            None => {
                                query(
                                    "INSERT INTO arquivos (caminho, last_modified, sincronizar) VALUES (?, ?, 'Sim')",
                                )
                                .bind(&path_str)
                                .bind(modified)
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

