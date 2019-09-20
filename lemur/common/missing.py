import arrow
from flask import current_app

from lemur.common.utils import is_weekend


def convert_validity_years(data):
    """
    Convert validity years to validity_start and validity_end

    :param data:
    :return:
    """
    if data.get("validity_years"):
        now = arrow.utcnow()
        data["validity_start"] = now.isoformat()

        end = now.shift(years=+int(data["validity_years"]))

        if not current_app.config.get("LEMUR_ALLOW_WEEKEND_EXPIRATION", True):
            if is_weekend(end):
                end = end.shift(days=-2)

        data["validity_end"] = end.isoformat()
    return data
