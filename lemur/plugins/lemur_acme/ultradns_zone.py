class Zone:
    """
    This class implements an Ultra DNS zone.
    """

    def __init__(self, _data, _client="Client"):
        self._data = _data
        self._client = _client

    @property
    def name(self):
        """
        Zone name, has a trailing "." at the end, which we manually remove.
        """
        return self._data["properties"]["name"][:-1]

    @property
    def authoritative_type(self):
        """
        Indicates whether the zone is setup as a PRIMARY or SECONDARY
        """
        return self._data["properties"]["type"]

    @property
    def record_count(self):
        return self._data["properties"]["resourceRecordCount"]

    @property
    def status(self):
        """
        Returns the status of the zone - ACTIVE, SUSPENDED, etc
        """
        return self._data["properties"]["status"]
