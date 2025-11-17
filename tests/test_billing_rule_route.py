from decimal import Decimal

def test_get_billing_rule_public(client, db_session):
    from parking.models import ParkingLot, BillingRule
    lot = ParkingLot(name='L2', address='addr', total_capacity=10, available_spots=10)
    db_session.add(lot)
    db_session.flush()
    br = BillingRule(parking_lot_id=lot.id, rule_name='r', free_duration_minutes=15, hourly_rate=Decimal('6.50'), daily_cap_rate=Decimal('20.00'))
    db_session.add(br)
    db_session.commit()
    r = client.get(f"/api/v1/parking-lots/{lot.id}/billing-rule")
    assert r.status_code == 200
    data = r.json()
    assert str(data['hourly_rate']) == '6.50'