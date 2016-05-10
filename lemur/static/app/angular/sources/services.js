'use strict';
angular.module('lemur')
  .service('SourceApi', function (LemurRestangular) {
    return LemurRestangular.all('sources');
  })
  .service('SourceService', function ($location,  SourceApi, PluginService) {
    var SourceService = this;
    SourceService.findSourcesByName = function (filterValue) {
      return SourceApi.getList({'filter[label]': filterValue})
        .then(function (sources) {
          return sources;
        });
    };

    SourceService.create = function (source) {
      return SourceApi.post(source);
    };

    SourceService.update = function (source) {
      return source.put();
    };

    SourceService.getPlugin = function (source) {
      return PluginService.getByName(source.pluginName).then(function (plugin) {
        source.plugin = plugin;
      });
    };
    return SourceService;
  });
