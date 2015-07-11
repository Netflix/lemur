'use strict';

angular.module('lemur')

  .controller('DestinationsCreateController', function ($scope, $modalInstance, PluginService, DestinationService, LemurRestangular){
    $scope.destination = LemurRestangular.restangularizeElement(null, {}, 'destinations');

    PluginService.get('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });
    $scope.save = function (destination) {
      DestinationService.create(destination).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };
  })

  .controller('DestinationsEditController', function ($scope, $modalInstance, DestinationService, DestinationApi, PluginService, editId) {
    DestinationApi.get(editId).then(function (destination) {
      $scope.destination = destination;
    });
    
    PluginService.get('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (destination) {
      DestinationService.update(destination).then(function () {
        $modalInstance.close();
      });
    }

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };
  });
