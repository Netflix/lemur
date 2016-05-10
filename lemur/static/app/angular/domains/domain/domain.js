'use strict';

angular.module('lemur')

  .controller('DomainsCreateController', function ($scope, $uibModalInstance, PluginService, DomainService, LemurRestangular){
    $scope.domain = LemurRestangular.restangularizeElement(null, {}, 'domains');

    $scope.save = function (domain) {
      DomainService.create(domain).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  })

  .controller('DomainsEditController', function ($scope, $uibModalInstance, DomainService, DomainApi, editId) {
    DomainApi.get(editId).then(function (domain) {
      $scope.domain = domain;
    });

    $scope.save = function (domain) {
      DomainService.update(domain).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  });
