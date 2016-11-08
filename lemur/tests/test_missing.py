import arrow

from freezegun import freeze_time


def test_convert_validity_years(session):
    from lemur.common.missing import convert_validity_years

    with freeze_time("2016-01-01"):
        data = convert_validity_years(dict(validity_years=2))

        assert data['validity_start'] == arrow.utcnow().date().isoformat()
        assert data['validity_end'] == arrow.utcnow().replace(years=+2).date().isoformat()

    with freeze_time("2015-01-10"):
        data = convert_validity_years(dict(validity_years=1))
        assert data['validity_end'] == arrow.utcnow().replace(years=+1, days=-2).date().isoformat()
