'use strict';

angular.module('lemur')

  .controller('UsersEditController', function ($scope, $uibModalInstance, UserApi, UserService, RoleService, ApiKeyService, toaster, editId) {
    UserApi.get(editId).then(function (user) {
      $scope.user = user;
      UserService.getApiKeys(user);
    });

    $scope.roleService = RoleService;
    $scope.apiKeyService = ApiKeyService;

    $scope.rolePage = 1;
    $scope.apiKeyPage = 1;

    $scope.save = function (user) {
      UserService.update(user).then(
        function () {
          toaster.pop({
            type: 'success',
            title: user.username,
            body: 'Successfully Updated!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: user.username,
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

    $scope.removeApiKey = function (idx) {
      UserApi.removeApiKey(idx).then(function () {
        toaster.pop({
          type: 'success',
          title: 'Removed API Key!',
          body: 'Successfully removed the api key!'
        });
      }, function(err) {
        toaster.pop({
          type: 'error',
          title: 'Failed to remove API Key!',
          body: 'lemur-bad-request',
          bodyOutputType: 'directive',
          directiveData: err,
          timeout: 100000
        });
      });
    };

    $scope.loadMoreRoles = function () {
      $scope.rolePage += 1;
      UserService.loadMoreRoles($scope.user, $scope.rolePage);
    };

    $scope.loadMoreApiKeys = function () {
      $scope.apiKeyPage += 1;
      UserService.loadMoreApiKeys($scope.user, $scope.apiKeyPage);
    };
  })

  .controller('UsersCreateController', function ($scope, $uibModalInstance, UserService, LemurRestangular, RoleService, ApiKeyService, toaster) {
    $scope.user = LemurRestangular.restangularizeElement(null, {}, 'users');
    $scope.roleService = RoleService;
    $scope.apiKeyService = ApiKeyService;

    $scope.save = function (user) {
      UserService.create(user).then(
        function () {
          toaster.pop({
            type: 'success',
            title: user.username,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: user.username,
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
