"""
.. module: lemur.plugins.base.v1
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import re
from threading import local
from typing import Optional, Dict, List, Any

from flask import current_app


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
    title: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    version = None
    author: Optional[str] = None
    author_url: Optional[str] = None
    resource_links = ()

    # Configuration specifics
    conf_key = None
    conf_title = None
    options: List[Dict[str, Any]] = []

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

    def get_option(self, name, options):
        user_opt = self.get_user_option(name, options)
        if user_opt is None:
            return None

        value = user_opt.get("value", user_opt.get("default"))
        if value is None:
            return None

        return self.validate_option_value(name, value)

    def validate_option_value(self, option_name, value):
        class_opt = self.get_server_options(option_name)
        if not class_opt:
            current_app.logger.warning("Plugin option server-defaults not found")
            return None
        opt_type = class_opt["type"]
        if opt_type == "str":
            validation = class_opt.get("validation")
            if not validation:
                return value
            if (callable(validation) and not validation(value)) or not re.match(validation, value):
                raise ValueError(f"Option '{option_name}' cannot be validated")
        elif opt_type == "select":
            available = class_opt.get("available")
            if available is None:
                return value
            if value not in available:
                raise ValueError(f"Option '{option_name}' doesn't match available options")
        return value

    def get_server_options(self, name):
        class_options = getattr(self, "options", [])
        for o in class_options:
            if o.get("name") == name:
                return o
        return None

    def get_user_option(self, name, options):
        for o in options:
            if o.get("name") == name:
                return o
        return None


class Plugin(IPlugin):
    """
    A plugin should be treated as if it were a singleton. The owner does not
    control when or how the plugin gets instantiated, nor is it guaranteed that
    it will happen, or happen more than once.
    """

    __version__ = 1
    __metaclass__ = PluginMount
