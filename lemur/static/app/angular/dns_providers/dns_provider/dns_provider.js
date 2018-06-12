'use strict';

angular.module('lemur')

  .controller('DnsProviderCreateController', function ($scope, $uibModalInstance, PluginService, DnsProviderService, LemurRestangular, toaster) {
    $scope.dns_provider = LemurRestangular.restangularizeElement(null, {}, 'dns_providers');

    DnsProviderService.getDnsProviderOptions().then(function(res) {
        $scope.options = res;
    });

    $scope.save = function (dns_provider) {
      DnsProviderService.create(dns_provider).then(
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
    DnsProviderService.getDnsProviderOptions().then(function(res) {
      $scope.options = res;
    });

    DnsProviderApi.get(editId).then(function (dns_provider) {
      $scope.dns_provider = dns_provider;
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
