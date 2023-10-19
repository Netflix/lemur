"""
.. module: lemur.plugins.base.manager
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson (kglisson@netflix.com)
"""
from flask import current_app
from lemur.common.managers import InstanceManager


# inspired by https://github.com/getsentry/sentry
class PluginManager(InstanceManager):
    def __iter__(self):
        return iter(self.all())

    def __len__(self):
        return sum(1 for i in self.all())

    def all(self, version=1, plugin_type=None):
        for plugin in sorted(
            super().all(), key=lambda x: x.get_title()
        ):
            if not plugin.type == plugin_type and plugin_type:
                continue
            if not plugin.is_enabled():
                continue
            if version is not None and plugin.__version__ != version:
                continue
            yield plugin

    def get(self, slug):
        for plugin in self.all(version=1):
            if plugin.slug == slug:
                return plugin
        for plugin in self.all(version=2):
            if plugin.slug == slug:
                return plugin
        current_app.logger.error(
            "Unable to find slug: {} in self.all version 1: {} or version 2: {}".format(
                slug, self.all(version=1), self.all(version=2)
            )
        )
        raise KeyError(slug)

    def first(self, func_name, *args, **kwargs):
        version = kwargs.pop("version", 1)
        for plugin in self.all(version=version):
            try:
                result = getattr(plugin, func_name)(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(
                    "Error processing %s() on %r: %s",
                    func_name,
                    plugin.__class__,
                    e,
                    extra={"func_arg": args, "func_kwargs": kwargs},
                    exc_info=True,
                )
                continue

            if result is not None:
                return result

    def register(self, cls):
        self.add("{}.{}".format(cls.__module__, cls.__name__))
        return cls

    def unregister(self, cls):
        self.remove("{}.{}".format(cls.__module__, cls.__name__))
        return cls
