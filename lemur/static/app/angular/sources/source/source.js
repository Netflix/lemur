'use strict';

angular.module('lemur')

  .controller('SourcesCreateController', function ($scope, $uibModalInstance, PluginService, SourceService, LemurRestangular){
    $scope.source = LemurRestangular.restangularizeElement(null, {}, 'sources');

    PluginService.getByType('source').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (source) {
      SourceService.create(source).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  })

  .controller('SourcesEditController', function ($scope, $uibModalInstance, SourceService, SourceApi, PluginService, editId) {
    SourceApi.get(editId).then(function (source) {
      $scope.source = source;
      PluginService.getByType('source').then(function (plugins) {
        $scope.plugins = plugins;
        _.each($scope.plugins, function (plugin) {
          if (plugin.slug === $scope.source.pluginName) {
            plugin.pluginOptions = $scope.source.sourceOptions;
            $scope.source.plugin = plugin;
          }
        });
      });
    });
    
    PluginService.getByType('source').then(function (plugins) {
      $scope.plugins = plugins;
      _.each($scope.plugins, function (plugin) {
        if (plugin.slug === $scope.source.pluginName) {
          plugin.pluginOptions = $scope.source.sourceOptions;
          $scope.source.plugin = plugin;
        }
      });
    });

    $scope.save = function (source) {
      SourceService.update(source).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  });
