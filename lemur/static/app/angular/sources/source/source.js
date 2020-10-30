'use strict';

angular.module('lemur')

  .controller('SourcesCreateController', function ($scope, $uibModalInstance, PluginService, SourceService, LemurRestangular, toaster){
    $scope.source = LemurRestangular.restangularizeElement(null, {}, 'sources');

    PluginService.getByType('source').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (source) {
      SourceService.create(source).then(
        function () {
          toaster.pop({
            type: 'success',
            title: source.label,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: source.label,
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

  .controller('SourcesEditController', function ($scope, $uibModalInstance, SourceService, SourceApi, PluginService, toaster, editId) {
    SourceApi.get(editId).then(function (source) {
      $scope.source = source;
      PluginService.getByType('source').then(function (plugins) {
        $scope.plugins = plugins;
        _.each($scope.plugins, function (plugin) {
          if (plugin.slug === $scope.source.plugin.slug) {
            plugin.pluginOptions = $scope.source.plugin.pluginOptions;
            $scope.source.plugin = plugin;
          }
        });
      });
    });

    $scope.save = function (source) {
      SourceService.update(source).then(
        function () {
          toaster.pop({
            type: 'success',
            title: source.label,
            body: 'Successfully Updated!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: source.label,
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
