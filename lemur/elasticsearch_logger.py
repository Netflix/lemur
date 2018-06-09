import datetime

from elasticsearch import Elasticsearch
from logging import getLogger, Handler, ERROR
from pytz import timezone


class ESHandler(Handler):
    def __init__(self, es, index):
        super().__init__()
        self.es = Elasticsearch(es)
        self.index = index
        getLogger("elasticsearch").setLevel(ERROR)
        getLogger("elasticsearch.trace").setLevel(ERROR)
        getLogger("urllib3").setLevel(ERROR)

    def emit(self, record):
        record.eventTime = datetime.datetime.now(timezone('US/Pacific')).isoformat()
        log_entry = self.format(record)

        # Push action to ES
        return self.es.index(index=self.index, doc_type="python_log", body=log_entry)
