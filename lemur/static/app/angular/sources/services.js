'use strict';
angular.module('lemur')
  .service('SourceApi', function (LemurRestangular) {
    return LemurRestangular.all('sources');
  })
  .service('SourceService', function ($location,  SourceApi, PluginService, toaster) {
    var SourceService = this;
    SourceService.findSourcesByName = function (filterValue) {
      return SourceApi.getList({'filter[label]': filterValue})
        .then(function (sources) {
          return sources;
        });
    };

    SourceService.create = function (source) {
      return SourceApi.post(source).then(
        function () {
          toaster.pop({
            type: 'success',
            title: source.label,
            body: 'Successfully created!'
          });
          $location.path('sources');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: source.label,
            body: 'Was not created! ' + response.data.message
          });
        });
    };

    SourceService.update = function (source) {
      return source.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: source.label,
            body: 'Successfully updated!'
          });
          $location.path('sources');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: source.label,
            body: 'Was not updated! ' + response.data.message
          });
        });
    };

    SourceService.getPlugin = function (source) {
      return PluginService.getByName(source.pluginName).then(function (plugin) {
        source.plugin = plugin;
      });
    };
    return SourceService;
  });
