from datetime import datetime, timezone, timedelta
from decimal import Decimal
import pytest

from parking.services import compute_fee, complete_parking_record
from parking.models import BillingRule, ParkingLot, ParkingRecord

def test_compute_fee_no_cap():
    entry = datetime(2025, 11, 16, 0, 0, tzinfo=timezone.utc)
    rule = type('R', (), {})()
    rule.free_duration_minutes = 15
    rule.hourly_rate = Decimal('5.00')
    rule.daily_cap_rate = None
    f1 = compute_fee(entry, entry + timedelta(minutes=10), rule)
    f2 = compute_fee(entry, entry + timedelta(minutes=90), rule)
    assert f1 == Decimal('0.00')
    assert f2 == Decimal('10.00')

def test_compute_fee_with_cap_cross_days():
    entry = datetime(2025, 11, 16, 0, 0, tzinfo=timezone.utc)
    rule = type('R', (), {})()
    rule.free_duration_minutes = 15
    rule.hourly_rate = Decimal('5.00')
    rule.daily_cap_rate = Decimal('20.00')
    f1 = compute_fee(entry, entry + timedelta(minutes=90), rule)
    f2 = compute_fee(entry, entry + timedelta(days=1, minutes=90), rule)
    f3 = compute_fee(entry, entry + timedelta(days=3), rule)
    assert f1 == Decimal('10.00')
    assert f2 == Decimal('30.00')
    assert f3 == Decimal('60.00')

def test_complete_parking_record_updates_fee(db_session):
    lot = ParkingLot(name='L1', address='addr', total_capacity=100, available_spots=99)
    db_session.add(lot)
    db_session.flush()
    br = BillingRule(parking_lot_id=lot.id, rule_name='r', free_duration_minutes=0, hourly_rate=Decimal('10.00'), daily_cap_rate=Decimal('25.00'))
    db_session.add(br)
    db_session.flush()
    rec = ParkingRecord(vehicle_id=1, parking_lot_id=lot.id, license_plate_snapshot='ABC', entry_time=datetime(2025, 11, 16, 0, 0, tzinfo=timezone.utc))
    db_session.add(rec)
    db_session.flush()
    r = complete_parking_record(db_session, rec.id, rec.entry_time + timedelta(minutes=150))
    db_session.commit()
    assert r.fee == Decimal('25.00')