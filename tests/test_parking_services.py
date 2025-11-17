from datetime import datetime, timedelta, timezone
from decimal import Decimal

def test_compute_fee_branches(client):
    from parking.services import compute_fee
    class Rule:
        free_duration_minutes = 15
        hourly_rate = Decimal("10.00")
        daily_cap_rate = Decimal("20.00")
    entry = datetime.now(timezone.utc)
    # exit earlier than entry
    assert compute_fee(entry, entry - timedelta(minutes=1), Rule()) == Decimal("0.00")
    # exactly free minutes
    assert compute_fee(entry, entry + timedelta(minutes=15), Rule()) == Decimal("0.00")
    # 1 hour charged
    assert compute_fee(entry, entry + timedelta(minutes=16), Rule()) == Decimal("10.00")
    # cap applies
    class Rule2:
        free_duration_minutes = 0
        hourly_rate = Decimal("30.00")
        daily_cap_rate = Decimal("20.00")
    assert compute_fee(entry, entry + timedelta(hours=2), Rule2()) == Decimal("20.00")

def test_service_none_paths(db_session):
    from parking.services import create_parking_entry, complete_parking_record, mark_payment_success
    # entry returns None when vehicle not exists
    assert create_parking_entry(db_session, "NOPE", 1) is None
    # complete record None
    assert complete_parking_record(db_session, 999999, None) is None
    # payment success None
    assert mark_payment_success(db_session, 999999, None) is None

def test_set_default_vehicle_direct(client, db_session):
    client.post("/api/v1/register", json={"phone_number": "15199999999", "password": "password151999"})
    token = client.post("/api/v1/login", data={"username": "15199999999", "password": "password151999"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/v1/vehicles", json={"license_plate": "SVC001"}, headers=headers)
    client.post("/api/v1/vehicles", json={"license_plate": "SVC002"}, headers=headers)
    from parking.models import Vehicle
    from parking.services import set_default_vehicle
    user_id = db_session.query(Vehicle).filter(Vehicle.license_plate == "SVC001").first().user_id
    v1 = db_session.query(Vehicle).filter(Vehicle.license_plate == "SVC001").first()
    v2 = db_session.query(Vehicle).filter(Vehicle.license_plate == "SVC002").first()
    set_default_vehicle(db_session, user_id, v2.id)
    v1 = db_session.query(Vehicle).filter(Vehicle.id == v1.id).first()
    v2 = db_session.query(Vehicle).filter(Vehicle.id == v2.id).first()
    assert v1.is_default is False and v2.is_default is True