'use strict';
angular.module('lemur')
  .service('DestinationApi', function (LemurRestangular) {
    return LemurRestangular.all('destinations');
  })
  .service('DestinationService', function ($location,  DestinationApi, PluginService) {
    var DestinationService = this;
    DestinationService.findDestinationsByName = function (filterValue) {
      return DestinationApi.getList({'filter[label]': filterValue})
        .then(function (destinations) {
          return destinations;
        });
    };

    DestinationService.create = function (destination) {
      return DestinationApi.post(destination);
    };

    DestinationService.update = function (destination) {
      return destination.put();
    };

    DestinationService.getPlugin = function (destination) {
      return PluginService.getByName(destination.pluginName).then(function (plugin) {
        destination.plugin = plugin;
      });
    };
    return DestinationService;
  });
