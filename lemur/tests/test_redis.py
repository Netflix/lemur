import fakeredis
import time
import sys


def test_write_and_read_from_redis():
    function = f"{__name__}.{sys._getframe().f_code.co_name}"

    red = fakeredis.FakeStrictRedis()
    key = f"{function}.last_success"
    value = int(time.time())
    assert red.set(key, value) is True
    assert (int(red.get(key)) == value) is True
