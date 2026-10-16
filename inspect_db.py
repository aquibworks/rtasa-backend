import os
from sqlalchemy import text
from app.db.session import SessionLocal

db = SessionLocal()
try:
    print("=== File sizes ===")
    for f in os.listdir("."):
        if f.startswith("rtasa.db"):
            print(f"  {f}: {os.path.getsize(f)/1024/1024:.2f} MB")

    print("\n=== Tables and row counts ===")
    rows = db.execute(text(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )).fetchall()
    for (name,) in rows:
        try:
            c = db.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar()
            print(f"  {name}: {c} rows")
        except Exception as e:
            print(f"  {name}: (error {e})")

    print("\n=== Page info ===")
    page_size = db.execute(text("PRAGMA page_size")).scalar()
    page_count = db.execute(text("PRAGMA page_count")).scalar()
    freelist_count = db.execute(text("PRAGMA freelist_count")).scalar()
    print(f"  page_size={page_size}  page_count={page_count}  freelist_count={freelist_count}")
    print(f"  total   = {page_size * page_count / 1024 / 1024:.2f} MB")
    print(f"  unused  = {page_size * freelist_count / 1024 / 1024:.2f} MB")
finally:
    db.close()
