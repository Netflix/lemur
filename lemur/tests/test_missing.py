import arrow


def test_convert_validity_years(session):
    from lemur.common.missing import convert_validity_years

    data = convert_validity_years(dict(validity_years=2))

    assert data['validity_start'] == arrow.utcnow().date().isoformat()
    assert data['validity_end'] == arrow.utcnow().replace(years=2).date().isoformat()
