from app.db.session import SessionLocal
from app.models.domain import EncryptedSecret, ShareRecord, ReconstructionToken

db = SessionLocal()
try:
    t = db.query(ReconstructionToken).delete()
    s = db.query(ShareRecord).delete()
    e = db.query(EncryptedSecret).delete()
    db.commit()

    # VACUUM must run outside a transaction
    db.close()
    db = SessionLocal()
    db.execute(__import__('sqlalchemy').text("VACUUM"))
    db.commit()

    print(f"Deleted secrets={e} shares={s} tokens={t}")
    print("VACUUM done - file size reduced.")
finally:
    db.close()
