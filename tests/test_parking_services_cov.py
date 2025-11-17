from datetime import datetime, timezone, timedelta
from parking.services import (
    update_layout_and_rebuild_spaces, get_layout,
    occupy_space, reserve_space, calculate_navigation_path, get_parking_stats
)
from parking.models import ParkingLot, Vehicle

def setup_admin_user_vehicle(client, db_session):
    from tests.test_parking_visualization import setup_admin
    from tests.test_parking_routers import setup_user_and_token
    admin = setup_admin(client, db_session)
    user = setup_user_and_token(client)
    v = client.post("/api/v1/vehicles", json={"license_plate": "COV002", "is_default": False}, headers=user).json()
    return admin, user, v

def create_lot(client, admin):
    return client.post("/api/v1/parking-lots", json={"name":"LotSC","address":"AddrSC","total_capacity":0,"available_spots":0}, headers=admin).json()

def test_occupy_via_services_with_license_plate_and_not_found(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = create_lot(client, admin)
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    update_layout_and_rebuild_spaces(db_session, lot['id'], 3, 3, grid, {"row":0,"col":0}, {"row":1,"col":2})
    db_session.commit()
    # find a space
    from parking.models import ParkingSpace
    spaces = db_session.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot['id']).all()
    sp = spaces[0]
    # license_plate branch on available space
    res = occupy_space(db_session, sp.id, None, "COV002")
    assert res is not None
    # choose another available space for not found and none cases
    sp_avail = next(s for s in spaces if s.id != sp.id and s.status.name == 'AVAILABLE')
    res2 = occupy_space(db_session, sp_avail.id, None, "NOPE")
    assert res2 is None
    # neither vehicle_id nor license_plate
    res3 = occupy_space(db_session, sp_avail.id, None, None)
    assert res3 is None

def test_reservation_complete_on_occupy_services(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = create_lot(client, admin)
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    update_layout_and_rebuild_spaces(db_session, lot['id'], 3, 3, grid, {"row":0,"col":0}, {"row":1,"col":2})
    db_session.commit()
    from parking.models import ParkingSpace
    sp = db_session.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot['id']).first()
    # make reservation
    me = client.get("/api/v1/users/me", headers=user).json()
    rsv = reserve_space(db_session, sp.id, me['id'], v['id'], datetime.now(timezone.utc)+timedelta(minutes=5))
    assert rsv is not None
    db_session.commit()
    # occupy to complete reservation
    res = occupy_space(db_session, sp.id, v['id'], None)
    assert res is not None
    assert rsv.status.name == 'COMPLETED'

def test_reserved_without_matching_reservation_returns_none(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = create_lot(client, admin)
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    update_layout_and_rebuild_spaces(db_session, lot['id'], 3, 3, grid, {"row":0,"col":0}, {"row":1,"col":2})
    db_session.commit()
    from parking.models import ParkingSpace
    sp = db_session.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot['id']).first()
    # reserve for v
    me = client.get("/api/v1/users/me", headers=user).json()
    reserve_space(db_session, sp.id, me['id'], v['id'], datetime.now(timezone.utc)+timedelta(minutes=5))
    db_session.commit()
    # ensure reserved
    assert db_session.query(ParkingSpace).filter(ParkingSpace.id == sp.id).first().status.name == 'RESERVED'
    # create another vehicle
    v2 = client.post("/api/v1/vehicles", json={"license_plate": "COV003", "is_default": False}, headers=user).json()
    # occupy with different vehicle -> None
    res = occupy_space(db_session, sp.id, v2['id'], None)
    assert res is None

def test_services_navigation_and_stats(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = create_lot(client, admin)
    grid = [["entrance","road","road","parking"],["road","road","road","exit"],["road","road","road","parking"]]
    update_layout_and_rebuild_spaces(db_session, lot['id'], 3, 4, grid, {"row":0,"col":0}, {"row":1,"col":3})
    db_session.commit()
    path = calculate_navigation_path(db_session, lot['id'], {"row":0,"col":0}, {"row":1,"col":3})
    assert path is not None and len(path) > 0
    stats = get_parking_stats(db_session, lot['id'])
    assert 'total_spaces' in stats

def test_navigation_with_invalid_cell_type_hits_skip(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = create_lot(client, admin)
    grid = [["entrance","invalid","exit"],["road","road","road"]]
    update_layout_and_rebuild_spaces(db_session, lot['id'], 2, 3, grid, {"row":0,"col":0}, {"row":0,"col":2})
    db_session.commit()
    path = calculate_navigation_path(db_session, lot['id'], {"row":0,"col":0}, {"row":0,"col":2})
    assert path is not None

def test_reserve_space_duplicate_in_services(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = create_lot(client, admin)
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    update_layout_and_rebuild_spaces(db_session, lot['id'], 3, 3, grid, {"row":0,"col":0}, {"row":1,"col":2})
    db_session.commit()
    from parking.models import ParkingSpace
    sp = db_session.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot['id']).first()
    me = client.get("/api/v1/users/me", headers=user).json()
    r1 = reserve_space(db_session, sp.id, me['id'], v['id'], datetime.now(timezone.utc)+timedelta(minutes=5))
    assert r1 is not None
    r2 = reserve_space(db_session, sp.id, me['id'], v['id'], datetime.now(timezone.utc)+timedelta(minutes=5))
    assert r2 is None