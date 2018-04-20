'use strict';

angular.module('lemur')

  .controller('DnsProviderCreateController', function ($scope, $uibModalInstance, PluginService, DnsProviderService, LemurRestangular, toaster) {
    $scope.dns_provider = LemurRestangular.restangularizeElement(null, {}, 'dns_providers');

    PluginService.getByType('dns_provider').then(function (plugins) {
      $scope.plugins = plugins;
    });

    PluginService.getByType('export').then(function (plugins) {
      $scope.exportPlugins = plugins;
    });

    $scope.save = function (dns_provider) {
      DnsProvider.create(dns_provider.then(
        function () {
          toaster.pop({
            type: 'success',
            title: dns_provider.label,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: dns_provider.label,
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

  .controller('DnsProviderEditController', function ($scope, $uibModalInstance, DnsProviderService, DnsProviderApi, PluginService, toaster, editId) {


    DnsProviderApi.get(editId).then(function (dns_provider) {
      $scope.dns_provider = dns_provider;

      PluginService.getByType('dns_provider').then(function (plugins) {
        $scope.plugins = plugins;

        _.each($scope.plugins, function (plugin) {
          if (plugin.slug === $scope.dns_provider.plugin.slug) {
            plugin.pluginOptions = $scope.dns_provider.plugin.pluginOptions;
            $scope.dns_provider.plugin = plugin;
            _.each($scope.dns_provider.plugin.pluginOptions, function (option) {
              if (option.type === 'export-plugin') {
                PluginService.getByType('export').then(function (plugins) {
                  $scope.exportPlugins = plugins;

                  _.each($scope.exportPlugins, function (plugin) {
                    if (plugin.slug === option.value.slug) {
                      plugin.pluginOptions = option.value.pluginOptions;
                      option.value = plugin;
                    }
                  });
                });
              }
            });
          }
        });
      });
    });

    $scope.save = function (dns_provider) {
      DnsProviderService.update(dns_provider).then(
        function () {
          toaster.pop({
            type: 'success',
            title: dns_provider.label,
            body: 'Successfully Updated!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: dns_provider.label,
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
