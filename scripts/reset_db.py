from sqlalchemy import text
from auth.database import engine, Base

# Import models to ensure tables are registered in metadata
from auth.models import user as user_model  # noqa: F401
from parking import models as parking_models  # noqa: F401
from wallet import models as wallet_models  # noqa: F401

def reset_database():
    with engine.begin() as conn:
        dialect = conn.dialect.name
        if dialect == "mysql":
            conn.execute(text("SET FOREIGN_KEY_CHECKS=0"))
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        if dialect == "mysql":
            conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))

if __name__ == "__main__":
    reset_database()
    print("Database dropped and recreated successfully.")