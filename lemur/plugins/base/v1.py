"""
.. module: lemur.plugins.base.v1
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from threading import local


# stolen from https://github.com/getsentry/sentry/
class PluginMount(type):
    def __new__(cls, name, bases, attrs):
        new_cls = type.__new__(cls, name, bases, attrs)
        if IPlugin in bases:
            return new_cls
        if new_cls.title is None:
            new_cls.title = new_cls.__name__
        if not new_cls.slug:
            new_cls.slug = new_cls.title.replace(" ", "-").lower()
        return new_cls


class IPlugin(local):
    """
    Plugin interface. Should not be inherited from directly.
    A plugin should be treated as if it were a singleton. The owner does not
    control when or how the plugin gets instantiated, nor is it guaranteed that
    it will happen, or happen more than once.
    >>> from lemur.plugins import Plugin
    >>>
    >>> class MyPlugin(Plugin):
    >>>     def get_title(self):
    >>>         return 'My Plugin'
    As a general rule all inherited methods should allow ``**kwargs`` to ensure
    ease of future compatibility.
    """

    # Generic plugin information
    title = None
    slug = None
    description = None
    version = None
    author = None
    author_url = None
    resource_links = ()

    # Configuration specifics
    conf_key = None
    conf_title = None
    options = {}

    # Global enabled state
    enabled = True
    can_disable = True

    def is_enabled(self):
        """
        Returns a boolean representing if this plugin is enabled.
        If ``project`` is passed, it will limit the scope to that project.
        >>> plugin.is_enabled()
        """
        if not self.enabled:
            return False
        if not self.can_disable:
            return True

        return True

    def get_conf_key(self):
        """
        Returns a string representing the configuration keyspace prefix for this plugin.
        """
        if not self.conf_key:
            self.conf_key = self.get_conf_title().lower().replace(" ", "_")
        return self.conf_key

    def get_conf_title(self):
        """
        Returns a string representing the title to be shown on the configuration page.
        """
        return self.conf_title or self.get_title()

    def get_title(self):
        """
        Returns the general title for this plugin.
        >>> plugin.get_title()
        """
        return self.title

    def get_description(self):
        """
        Returns the description for this plugin. This is shown on the plugin configuration
        page.
        >>> plugin.get_description()
        """
        return self.description

    def get_resource_links(self):
        """
        Returns a list of tuples pointing to various resources for this plugin.
        >>> def get_resource_links(self):
        >>>     return [
        >>>         ('Documentation', 'https://lemur.readthedocs.io'),
        >>>         ('Bug Tracker', 'https://github.com/Netflix/lemur/issues'),
        >>>         ('Source', 'https://github.com/Netflix/lemur'),
        >>>     ]
        """
        return self.resource_links

    @staticmethod
    def get_option(name, options):
        for o in options:
            if o.get("name") == name:
                return o.get("value", o.get("default"))


class Plugin(IPlugin):
    """
    A plugin should be treated as if it were a singleton. The owner does not
    control when or how the plugin gets instantiated, nor is it guaranteed that
    it will happen, or happen more than once.
    """

    __version__ = 1
    __metaclass__ = PluginMount
