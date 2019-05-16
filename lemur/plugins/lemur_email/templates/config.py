import os
import arrow
from jinja2 import Environment, FileSystemLoader, select_autoescape

from lemur.plugins.utils import get_plugin_option

loader = FileSystemLoader(searchpath=os.path.dirname(os.path.realpath(__file__)))
env = Environment(
    loader=loader,  # nosec: potentially dangerous types esc.
    autoescape=select_autoescape(["html", "xml"]),
)


def human_time(time):
    return arrow.get(time).format("dddd, MMMM D, YYYY")


def interval(options):
    return get_plugin_option("interval", options)


def unit(options):
    return get_plugin_option("unit", options)


env.filters["time"] = human_time
env.filters["interval"] = interval
env.filters["unit"] = unit
