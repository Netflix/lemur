import datetime
import logging
from logging import getLogger, Handler

from elasticsearch import Elasticsearch
from pytz import timezone


class ESHandler(Handler):
    def __init__(self, es, index, elasticsearch_logging_level="error"):
        super().__init__()
        self.es = Elasticsearch(es)
        self.index = index

        if elasticsearch_logging_level == "info":
            level = logging.INFO
        elif elasticsearch_logging_level == "critical":
            level = logging.CRITICAL
        elif elasticsearch_logging_level == "error":
            level = logging.ERROR
        elif elasticsearch_logging_level == "warning":
            level = logging.WARNING
        elif elasticsearch_logging_level == "debug":
            level = logging.DEBUG

        getLogger("elasticsearch").setLevel(level)
        getLogger("elasticsearch.trace").setLevel(level)
        getLogger("urllib3").setLevel(level)

    def emit(self, record):
        record.eventTime = datetime.datetime.now(timezone('US/Pacific')).isoformat()
        log_entry = self.format(record)

        # Push action to ES
        return self.es.index(index=self.index, doc_type="python_log", body=log_entry)
