'use strict';

angular.module('lemur')

  .controller('PolicesCreateController', function ($scope, $uibModalInstance, PluginService, PolicesService, LemurRestangular, toaster){
    $scope.polices = LemurRestangular.restangularizeElement(null, {}, 'polices');

    $scope.save = function (polices) {
      PolicesService.create(polices).then(
        function () {
          toaster.pop({
            type: 'success',
            title: polices.name,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: polices,
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

  .controller('PolicesEditController', function ($scope, $uibModalInstance, PolicesService, PolicesApi, toaster, editId) {
    PolicesApi.get(editId).then(function (polices) {
      $scope.polices = polices;
    });

    $scope.save = function (polices) {
      PolicesService.update(polices).then(
        function () {
          toaster.pop({
            type: 'success',
            title: polices.name,
            body: 'Successfully Edited!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: polices,
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