from pathlib import Path

from app.db import connection


def run() -> None:
    migration_dir = Path(__file__).resolve().parent.parent / "migrations"
    with connection() as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
        cur.execute("SELECT filename FROM schema_migrations")
        applied = {row["filename"] for row in cur.fetchall()}
        for file in sorted(migration_dir.glob("*.sql")):
            if file.name in applied:
                continue
            cur.execute(file.read_text(encoding="utf-8"))
            cur.execute("INSERT INTO schema_migrations (filename) VALUES (%s)", (file.name,))
            print(f"Applied migration {file.name}")
    from app.learning_library import ensure_learning_library
    ensure_learning_library()


if __name__ == "__main__":
    run()
