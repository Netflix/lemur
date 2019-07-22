class Record:
    """
    This class implements an Ultra DNS record.
    Accepts the response from the API call as the argument.
    """

    def __init__(self, _data):
        # Since we are dealing with only TXT records for Lemur, we expect only 1 RRSet in the response.
        # Thus we default to picking up the first entry (_data["rrsets"][0]) from the response.
        self._data = _data["rrSets"][0]

    @property
    def name(self):
        return self._data["ownerName"]

    @property
    def rrtype(self):
        return self._data["rrtype"]

    @property
    def rdata(self):
        return self._data["rdata"]

    @property
    def ttl(self):
        return self._data["ttl"]
