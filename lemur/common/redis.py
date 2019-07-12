import redis
from flask import current_app

class RedisHandler():
    def __init__(self, host=current_app.config.get('REDIS_HOST', 'localhost'),
                 port=current_app.config.get('REDIS_PORT', 6379),
                 db=current_app.config.get('REDIS_DB', 0)):

        self.host = host
        self.port = port
        self.db = db

    def redis(self, db=0):
        red = redis.StrictRedis(host=self.host, port=self.port, db=self.db, charset="utf-8", decode_responses=True)
        return red


def redis_get(key, default=None):
    red = RedisHandler().redis_sync()
    v = red.get(key)
    if not v:
        return default
    return v
