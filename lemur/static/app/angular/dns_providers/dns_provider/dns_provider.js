'use strict';

angular.module('lemur')

  .controller('DnsProviderCreateController', function ($scope, $uibModalInstance, PluginService, DnsProviderService, LemurRestangular, toaster) {
    $scope.dns_provider = LemurRestangular.restangularizeElement(null, {}, 'dns_providers');

    PluginService.getByName('acme-issuer').then(function (acme) {
        $scope.acme = acme;
    });

    PluginService.getByType('dns_provider').then(function (plugins) {
      $scope.plugins = plugins;
    });

    PluginService.getByType('export').then(function (plugins) {
      $scope.exportPlugins = plugins;
    });

    $scope.save = function (dns_provider) {
      DnsProviderService.create(dns_provider.then(
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
        }));
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  })

  .controller('DnsProviderEditController', function ($scope, $uibModalInstance, DnsProviderService, DnsProviderApi, PluginService, toaster, editId) {


    DnsProviderApi.get(editId).then(function (dns_provider) {
      $scope.dns_provider = dns_provider;

      PluginService.getByName('acme-issuer').then(function (acme) {
        $scope.acme = acme;

        _.each($scope.acme, function (opts) {
          console.log(opts);
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
