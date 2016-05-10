'use strict';

angular.module('lemur')

  .controller('DestinationsCreateController', function ($scope, $uibModalInstance, PluginService, DestinationService, LemurRestangular){
    $scope.destination = LemurRestangular.restangularizeElement(null, {}, 'destinations');

    PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (destination) {
      DestinationService.create(destination).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  })

  .controller('DestinationsEditController', function ($scope, $uibModalInstance, DestinationService, DestinationApi, PluginService, editId) {
    DestinationApi.get(editId).then(function (destination) {
      $scope.destination = destination;
      PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
        _.each($scope.plugins, function (plugin) {
          if (plugin.slug === $scope.destination.pluginName) {
            plugin.pluginOptions = $scope.destination.destinationOptions;
            $scope.destination.plugin = plugin;
          }
        });
      });
    });
    
    $scope.save = function (destination) {
      DestinationService.update(destination).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  });
