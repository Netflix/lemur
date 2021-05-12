"""
Helper Class for Redis

"""
import redis
import sys
from flask import current_app
from sentry_sdk import capture_exception

from lemur.factory import create_app

if current_app:
    flask_app = current_app
else:
    flask_app = create_app()


class RedisHandler:
    def __init__(self, host=flask_app.config.get('REDIS_HOST', 'localhost'),
                 port=flask_app.config.get('REDIS_PORT', 6379),
                 db=flask_app.config.get('REDIS_DB', 0)):
        self.host = host
        self.port = port
        self.db = db

    def redis(self, db=0):
        # The decode_responses flag here directs the client to convert the responses from Redis into Python strings
        # using the default encoding utf-8.  This is client specific.
        function = f"{__name__}.{sys._getframe().f_code.co_name}"
        try:
            red = redis.StrictRedis(host=self.host, port=self.port, db=self.db, encoding="utf-8", decode_responses=True)
            red.set("test", 0)
        except redis.ConnectionError:
            log_data = {
                "function": function,
                "message": "Redis Connection error",
                "host": self.host,
                "port": self.port
            }
            current_app.logger.error(log_data)
            capture_exception()
        return red


def redis_get(key, default=None):
    red = RedisHandler().redis()
    try:
        v = red.get(key)
    except redis.exceptions.ConnectionError:
        v = None
    if not v:
        return default
    return v
