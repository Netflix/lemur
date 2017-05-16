'use strict';

angular.module('lemur')

  .controller('DomainsCreateController', function ($scope, $uibModalInstance, PluginService, DomainService, LemurRestangular, toaster){
    $scope.domain = LemurRestangular.restangularizeElement(null, {}, 'domains');

    $scope.save = function (domain) {
      DomainService.create(domain).then(
        function () {
          toaster.pop({
            type: 'success',
            title: domain.name,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: domain,
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

  .controller('DomainsEditController', function ($scope, $uibModalInstance, DomainService, DomainApi, toaster, editId) {
    DomainApi.get(editId).then(function (domain) {
      $scope.domain = domain;
    });

    $scope.save = function (domain) {
      DomainService.update(domain).then(
        function () {
          toaster.pop({
            type: 'success',
            title: domain,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: domain,
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
