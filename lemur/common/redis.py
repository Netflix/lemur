import redis
from asgiref.sync import sync_to_async
from flask import current_app


class RedisHandler():
    def __init__(self, host=current_app.config.get('REDIS_HOST', 'localhost'),
                 port=current_app.config.get('REDIS_PORT', 6379),
                 db=current_app.config.get('REDIS_DB', 0)):

        self.host = host
        self.port = port
        self.db = db

    async def redis(self, db=0):
        red = await sync_to_async(redis.StrictRedis)(host=self.host, port=self.port, db=self.db, charset="utf-8",
                                                     decode_responses=True)
        return red

    def redis_sync(self, db=0):
        red = redis.StrictRedis(host=self.host, port=self.port, db=self.db, charset="utf-8", decode_responses=True)
        return red


async def redis_get(key, default=None):
    red = await RedisHandler().redis()
    v = await sync_to_async(red.get)(key)
    if not v:
        return default
    return v


def redis_get_sync(key, default=None):
    red = RedisHandler().redis_sync()
    v = red.get(key)
    if not v:
        return default
    return v
