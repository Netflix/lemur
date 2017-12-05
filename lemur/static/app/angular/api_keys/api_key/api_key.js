'use strict';

angular.module('lemur')
  .controller('ApiKeysCreateController', function ($scope, $uibModalInstance, PluginService, ApiKeyService, UserService, LemurRestangular, toaster) {
    $scope.apiKey = LemurRestangular.restangularizeElement(null, {}, 'keys');

    $scope.origin = window.location.origin;

    $scope.save = function (apiKey) {
      ApiKeyService.create(apiKey).then(
        function (responseBody) {
          toaster.pop({
            type: 'success',
            title: 'Success!',
            body: 'Successfully Created API Token!'
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

    $scope.userService = UserService;
  })
  .controller('ApiKeysEditController', function ($scope, $uibModalInstance, ApiKeyService, UserService, LemurRestangular, toaster, editId) {
    LemurRestangular.one('keys', editId).customGET('described').then(function(apiKey) {
      $scope.apiKey = apiKey;
      $scope.selectedUser = apiKey.user;
    });

    $scope.origin = window.location.origin;

    $scope.save = function (apiKey) {
      ApiKeyService.update(apiKey).then(
        function (responseBody) {
          toaster.pop({
            type: 'success',
            title: 'Success',
            body: 'Successfully updated API Token!'
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

    $scope.userService = UserService;
  });
