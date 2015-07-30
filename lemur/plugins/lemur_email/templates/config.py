from jinja2 import Environment, PackageLoader

loader = PackageLoader('lemur')
env = Environment(loader=loader)
