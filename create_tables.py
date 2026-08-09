from app.db.session import engine, Base

from app.models.secret import Secret, Share


print("Creating database tables...")

Base.metadata.create_all(bind=engine)

print("Tables created successfully")