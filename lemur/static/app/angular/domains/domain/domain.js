'use strict';

angular.module('lemur')

  .controller('DomainsCreateController', function ($scope, $modalInstance, PluginService, DomainService, LemurRestangular){
    $scope.domain = LemurRestangular.restangularizeElement(null, {}, 'domains');

    $scope.save = function (domain) {
      DomainService.create(domain).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };
  })

  .controller('DomainsEditController', function ($scope, $modalInstance, DomainService, DomainApi, editId) {
    DomainApi.get(editId).then(function (domain) {
      $scope.domain = domain;
    });

    $scope.save = function (domain) {
      DomainService.update(domain).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };
  });
