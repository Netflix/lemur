import os
from jinja2 import Environment, FileSystemLoader

loader = FileSystemLoader(searchpath=os.path.dirname(os.path.realpath(__file__)))
env = Environment(loader=loader)
