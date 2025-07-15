# FileSentinel

**FileSentinel** is a Rust application that monitors a directory for file changes (added, modified, deleted) and synchronizes this information to a SQLite database. It tracks the file path, last modification time, the user who changed the file, and the type of action.

## Features

- Monitors any directory for file changes in real time
- Supports filtering by file extension (e.g. `jpg,jpeg,png` or `*` for all)
- Logs who changed the file (owner)
- Records actions: added, modified, deleted
- Configurable log level (error, warn, info, debug, trace)
- Easy integration with SQLite

## Usage

```bash
cargo run -- --path /folder/to/monitor
```

### Options

- `--path` (required): Directory to monitor
- `--database`: SQLite database URL (default: `sqlite://vigil.db`)
- `--extensions`: File extensions to monitor (comma separated, default: `jpg,jpeg`, use `*` for all)
- `--log-level`: Log level (`error`, `warn`, `info`, `debug`, `trace`, default: `info`)

### Examples

Monitor all files:
```bash
cargo run -- --path /folder --extensions '*'
```

Monitor only text and log files:
```bash
cargo run -- --path /folder --extensions 'txt,log'
```

Set log level to debug:
```bash
cargo run -- --path /folder --log-level debug
```

Use a custom database file:
```bash
cargo run -- --path /folder --database sqlite://custom.db
```

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS arquivos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caminho TEXT UNIQUE NOT NULL,
    last_modified DATETIME NOT NULL,
    sincronizar TEXT CHECK(sincronizar IN ('Sim', 'Nao')) NOT NULL,
    usuario TEXT NOT NULL DEFAULT 'unknown',
    action TEXT CHECK(action IN ('added', 'modified', 'deleted')) NOT NULL DEFAULT 'added'
);
```

## License

MIT
