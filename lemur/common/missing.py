import arrow
from flask import current_app

from lemur.common.utils import is_weekend


def convert_validity_years(data):
    """
    Convert validity years to validity_start and validity_end

    :param data:
    :return:
    """
    if data.get('validity_years'):
        now = arrow.utcnow()
        data['validity_start'] = now.isoformat()

        end = now.replace(years=+int(data['validity_years']))
        # some CAs want to see exactly two years validity, and not two years plus one day, as is the case currently
        # 1/25/2019 + 2 years ==> 1/25/2019 (two years and 1 day extra, violating the 2 year's limit)
        end = end.replace(days=-1)
        if not current_app.config.get('LEMUR_ALLOW_WEEKEND_EXPIRATION', True):
            if is_weekend(end):
                end = end.replace(days=-2)

        data['validity_end'] = end.isoformat()
    return data
