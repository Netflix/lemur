'use strict';

angular.module('lemur')

  .controller('DestinationsCreateController', function ($scope, $uibModalInstance, PluginService, DestinationService, LemurRestangular, toaster){
    $scope.destination = LemurRestangular.restangularizeElement(null, {}, 'destinations');

    PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (destination) {
      DestinationService.create(destination).then(
       function () {
          toaster.pop({
            type: 'success',
            title: destination.label,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: destination.label,
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  })

  .controller('DestinationsEditController', function ($scope, $uibModalInstance, DestinationService, DestinationApi, PluginService, toaster, editId) {
    DestinationApi.get(editId).then(function (destination) {
      $scope.destination = destination;
      PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
        _.each($scope.plugins, function (plugin) {
          if (plugin.slug === $scope.destination.pluginName) {
            $scope.destination.plugin = plugin;
          }
        });
      });
    });

    $scope.save = function (destination) {
      DestinationService.update(destination).then(
        function () {
          toaster.pop({
            type: 'success',
            title: destination.label,
            body: 'Successfully Updated!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: destination.label,
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });
        });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  });
