'use strict';

angular.module('lemur')
  .controller('ApiKeysCreateController', function ($scope, $uibModalInstance, PluginService, ApiKeyService, LemurRestangular, toaster) {
    $scope.apiKey = LemurRestangular.restangularizeElement(null, {}, 'keys');

    $scope.save = function (apiKey) {
      ApiKeyService.create(apiKey).then(
        function (responseBody) {
          toaster.pop({
            type: 'success',
            title: 'Success!',
            body: 'Successfully Created JWT!'
          });
          $scope.jwt = responseBody.jwt;
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: apiKey.name || 'Unnamed Api Key',
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

    $scope.close = function() {
      $uibModalInstance.close();
    };
  })
  .controller('ApiKeysEditController', function ($scope, $uibModalInstance, ApiKeyService, LemurRestangular, toaster, editId) {
    LemurRestangular.one('keys', editId).customGET('described').then(function(apiKey) {
      $scope.apiKey = apiKey;
    });

    $scope.save = function (apiKey) {
      ApiKeyService.update(apiKey).then(
        function (responseBody) {
          toaster.pop({
            type: 'success',
            title: 'Success',
            body: 'Successfully updated JWT!'
          });
          $scope.jwt = responseBody.jwt;
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: apiKey.name || 'Unnamed API Key',
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

    $scope.close = function() {
      $uibModalInstance.close();
    };
  });
