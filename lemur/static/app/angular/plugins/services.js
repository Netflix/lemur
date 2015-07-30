'use strict';

angular.module('lemur')
  .service('PluginApi', function (LemurRestangular) {
    return LemurRestangular.all('plugins');
  })
  .service('PluginService', function (PluginApi) {
    var PluginService = this;
    PluginService.get = function () {
      return PluginApi.getList().then(function (plugins) {
        return plugins;
      });
    };

    PluginService.getByType = function (type) {
      return PluginApi.getList({'type': type}).then(function (plugins) {
        return plugins;
      });
    };

    PluginService.getByName = function (pluginName) {
      return PluginApi.customGET(pluginName).then(function (plugin) {
        return plugin;
      });
    };

    return PluginService;
  });
