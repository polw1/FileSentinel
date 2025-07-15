use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::fs;
use std::env;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{query, query_scalar, SqlitePool};
use clap::{Arg, Command};
use log::{info, debug, error};

const DATABASE_URL: &str = "sqlite://vigil.db";

fn create_database_file(database_url: &str) {
    let path = PathBuf::from(database_url.trim_start_matches("sqlite://"));
    if !path.exists() {
        fs::File::create(path).expect("Failed to create database file");
    }
}

fn get_last_modified(path: &PathBuf) -> Option<NaiveDateTime> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    DateTime::<Utc>::from_timestamp(secs, 0).map(|dt| dt.naive_utc())
}

fn get_file_owner(path: &PathBuf) -> String {
    use std::process::Command as SysCommand;
    
    // Tenta obter o proprietário do arquivo usando o comando 'stat'
    let output = SysCommand::new("stat")
        .arg("-c")
        .arg("%U")  // %U retorna o nome de usuário do proprietário
        .arg(path)
        .output();
    
    match output {
        Ok(result) if result.status.success() => {
            String::from_utf8_lossy(&result.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    
}

fn parse_cli_args() -> (String, String, String, Vec<String>) {
    let matches = Command::new("FileSentinel")
        .version("0.1.0")
        .author("PDC <pdc@example.com>")
        .about("FileSentinel: Monitors a directory for file changes and syncs them to a SQLite database. Tracks who changed, what changed, and the action (added, modified, deleted).\n\nUSAGE EXAMPLES:\n  Monitor all files in a folder (default extensions: jpg,jpeg):\n    file-sentinel --path /folder/to/monitor\n\n  Monitor all extensions:\n    file-sentinel --path /folder --extensions '*'\n\n  Monitor only specific extensions:\n    file-sentinel --path /folder --extensions 'txt,log,png'\n\n  Set log level to debug:\n    file-sentinel --path /folder --log-level debug\n\n  Use a custom database file:\n    file-sentinel --path /folder --database sqlite://custom.db\n")
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .value_name("PATH")
                .help("Directory path to monitor (required)")
                .required(true)
        )
        .arg(
            Arg::new("database")
                .short('d')
                .long("database")
                .value_name("DATABASE_URL")
                .help("SQLite database URL. Example: sqlite://vigil.db")
                .default_value(DATABASE_URL)
        )
        .arg(
            Arg::new("extensions")
                .short('e')
                .long("extensions")
                .value_name("EXTENSIONS")
                .help("File extensions to monitor (comma separated). Use '*' for all extensions. Examples: 'jpg,jpeg,png' or 'txt,log' or '*' (default: jpg,jpeg)")
                .default_value("jpg,jpeg")
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level: error, warn, info, debug, trace (default: info)")
                .default_value("info")
        )
        .get_matches();

    let watch_path = matches.get_one::<String>("path").unwrap().clone();
    let database_url = matches.get_one::<String>("database").unwrap().clone();
    let log_level = matches.get_one::<String>("log-level").unwrap().clone();
    let extensions_str = matches.get_one::<String>("extensions").unwrap();
    
    let extensions = if extensions_str == "*" {
        vec!["*".to_string()]
    } else {
        extensions_str
            .split(',')
            .map(|ext| ext.trim().to_lowercase())
            .filter(|ext| !ext.is_empty())
            .collect()
    };
    
    (watch_path, database_url, log_level, extensions)
}

fn should_monitor_file(path: &Path, extensions: &[String]) -> bool {
    // Se a lista contém "*", monitora todos os arquivos
    if extensions.contains(&"*".to_string()) {
        return true;
    }
    
    // Verifica se a extensão do arquivo está na lista de extensões monitoradas
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            extensions.contains(&ext)
        })
        .unwrap_or(false)
}

fn init_logger(log_level: &str) {
    use env_logger::Env;
    
    let level = match log_level.to_lowercase().as_str() {
        "error" => "error",
        "warn" => "warn", 
        "info" => "info",
        "debug" => "debug",
        "trace" => "trace",
        _ => "info"
    };
    
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}

async fn handle_file_event(path: &Path, action: &str, pool: &SqlitePool) {
    debug!("📸 File detected: {} (action: {})", path.display(), action);
    
    if let Some(modified) = get_last_modified(&PathBuf::from(path)) {
        debug!("🕒 Last modified: {}", modified);
        let path_str = path.to_string_lossy().to_string();
        let file_owner = get_file_owner(&PathBuf::from(path));
        debug!("📂 Path: {}", path_str);
        debug!("👤 File owner: {}", file_owner);

        let existing: Option<NaiveDateTime> = query_scalar(
            "SELECT last_modified FROM arquivos WHERE caminho = ?",
        )
        .bind(&path_str)
        .fetch_optional(pool)
        .await
        .unwrap();
        debug!("🔍 Checking existence in database...");
        debug!("🔎 Existing: {:?}", existing);

        let existing_action: Option<String> = query_scalar(
            "SELECT action FROM arquivos WHERE caminho = ?",
        )
        .bind(&path_str)
        .fetch_optional(pool)
        .await
        .unwrap();
        debug!("🔎 Previous action: {:?}", existing_action);

        match existing {
            Some(last_mod) => {
                // Só atualiza se a ação anterior não for "added"
                if (modified > last_mod || action == "modified") && existing_action.as_deref() != Some("added") {
                    query(
                        "UPDATE arquivos SET sincronizar = 'Sim', last_modified = ?, usuario = ?, action = ? WHERE caminho = ?",
                    )
                    .bind(modified)
                    .bind(&file_owner)
                    .bind(action)
                    .bind(&path_str)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        error!("❌ Error updating file in database: {}", e);
                        error!("📂 Path: {}", path_str);
                        error!("🕒 Modified: {}", modified);
                        error!("👤 User: {}", file_owner);
                        error!("🎯 Action: {}", action);
                        e
                    })
                    .unwrap();
                    info!("🔁 Updated: {} (user: {}, action: {})", path_str, file_owner, action);
                }
            }
            None => {
                debug!("📥 Inserting new file into database...");
                query(
                    "INSERT INTO arquivos (caminho, last_modified, sincronizar, usuario, action) VALUES (?, ?, 'Sim', ?, ?)",
                )
                .bind(&path_str)
                .bind(modified)
                .bind(&file_owner)
                .bind(action)
                .execute(pool)
                .await
                .map_err(|e| {
                    error!("❌ Error inserting file into database: {}", e);
                    error!("📂 Path: {}", path_str);
                    error!("🕒 Modified: {}", modified);
                    error!("👤 User: {}", file_owner);
                    error!("🎯 Action: {}", action);
                    e
                })
                .unwrap();
                info!("➕ Inserted new: {} (user: {}, action: {})", path_str, file_owner, action);
            }
        }
    }
}

async fn handle_file_deletion(path: &Path, pool: &SqlitePool) {
    let path_str = path.to_string_lossy().to_string();
    debug!("🗑️ File deleted: {}", path_str);
    
    // Para arquivos deletados, não podemos obter o proprietário atual
    // Então mantemos o usuário anterior e atualizamos apenas a ação
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT usuario FROM arquivos WHERE caminho = ?",
    )
    .bind(&path_str)
    .fetch_optional(pool)
    .await
    .unwrap();
    
    match existing {
        Some(user) => {
            query(
                "UPDATE arquivos SET action = 'deleted', sincronizar = 'Sim' WHERE caminho = ?",
            )
            .bind(&path_str)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("❌ Error updating deleted file in database: {}", e);
                error!("📂 Path: {}", path_str);
                e
            })
            .unwrap();
            info!("🗑️ Marked as deleted: {} (user: {})", path_str, user);
        }
        None => {
            debug!("🤷 Deleted file not found in database: {}", path_str);
        }
    }
}

#[tokio::main]
async fn main() -> notify::Result<()> {
    let (watch_path, database_url, log_level, extensions) = parse_cli_args();
    
    init_logger(&log_level);
    create_database_file(&database_url); 
    let pool = SqlitePool::connect(&database_url).await.expect("failed to connect to db");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS arquivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caminho TEXT UNIQUE NOT NULL,
            last_modified DATETIME NOT NULL,
            sincronizar TEXT CHECK(sincronizar IN ('Sim', 'Nao')) NOT NULL,
            usuario TEXT NOT NULL DEFAULT 'unknown',
            action TEXT CHECK(action IN ('added', 'modified', 'deleted')) NOT NULL DEFAULT 'added'
        )"
    ).execute(&pool).await.unwrap();

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(move |res| {
        tx.send(res).unwrap();
    }, Config::default())?;
    watcher.watch(Path::new(&watch_path), RecursiveMode::Recursive)?;

    info!("🟢 Monitoring changes in: {}", watch_path);

    while let Ok(Ok(event)) = rx.recv() {
        match event.kind {
            EventKind::Create(_) => {
                for path in event.paths {
                    if should_monitor_file(&path, &extensions) {
                        handle_file_event(&path, "added", &pool).await;
                    } else {
                        debug!("� File ignored due to extension: {}", path.display());
                    }
                }
            }
            EventKind::Modify(_) => {
                for path in event.paths {
                    if should_monitor_file(&path, &extensions) {
                        handle_file_event(&path, "modified", &pool).await;
                    } else {
                        debug!("🔇 File ignored due to extension: {}", path.display());
                    }
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if should_monitor_file(&path, &extensions) {
                        handle_file_deletion(&path, &pool).await;
                    } else {
                        debug!("🔇 File ignored due to extension: {}", path.display());
                    }
                }
            }
            _ => {
                // Outros tipos de eventos ignorados
            }
        }
    }

    Ok(())
}

