import os
import arrow
from jinja2 import Environment, FileSystemLoader

loader = FileSystemLoader(searchpath=os.path.dirname(os.path.realpath(__file__)))
env = Environment(loader=loader)


def human_time(time):
    return arrow.get(time).format('dddd, MMMM D, YYYY')

env.filters['time'] = human_time
