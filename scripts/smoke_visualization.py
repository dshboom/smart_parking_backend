from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from datetime import datetime, timezone
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app
from auth.database import Base, get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
Base.metadata.create_all(bind=engine)

client = TestClient(app)

def setup_admin():
    r = client.post("/api/v1/register", json={"phone_number": "19990000000", "password": "admin"})
    login = client.post("/api/v1/login", data={"username": "19990000000", "password": "admin"})
    tok = login.json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}

def setup_user():
    r = client.post("/api/v1/register", json={"phone_number": "18880000000", "password": "user"})
    login = client.post("/api/v1/login", data={"username": "18880000000", "password": "user"})
    tok = login.json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}

admin = setup_admin()
user = setup_user()

lot = client.post("/api/v1/parking-lots", json={"name": "LotSMK", "address": "AddrSMK", "total_capacity": 0, "available_spots": 0}, headers=admin).json()
grid = [["entrance","road","parking"],["road","road","parking"],["road","road","exit"]]
layout = client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":2,"col":2}}, headers=admin)
print("layout:", layout.status_code, layout.json())
spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
print("spaces:", spaces)