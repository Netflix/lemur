import arrow


def dates(data):
    # ensure that validity_start and validity_end are always set
    if not(data.get('validity_start') and data.get('validity_end')):
        if data.get('validity_years'):
            num_years = data['validity_years']
            now = arrow.utcnow()
            then = now.replace(years=+int(num_years))

            data['validity_start'] = now.isoformat()
            data['validity_end'] = then.isoformat()
