'use strict';

angular.module('lemur')

  .controller('RolesEditController', function ($scope, $uibModalInstance, RoleApi, RoleService, UserService, toaster, editId) {
    RoleApi.get(editId).then(function (role) {
      $scope.role = role;
      RoleService.getUsers(role);
    });

    $scope.save = function (role) {
      RoleService.update(role).then(
        function () {
          toaster.pop({
            type: 'success',
            title: role.name,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: role.name,
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

    $scope.userPage = 1;
    $scope.loadMoreRoles = function () {
      $scope.userPage += 1;
      RoleService.loadMoreUsers($scope.role, $scope.userPage);
    };

    $scope.userService = UserService;
    $scope.roleService = RoleService;
  })

  .controller('RolesCreateController', function ($scope,$uibModalInstance, RoleApi, RoleService, UserService, LemurRestangular, toaster) {
    $scope.role = LemurRestangular.restangularizeElement(null, {}, 'roles');
    $scope.userService = UserService;

    $scope.save = function (role) {
      RoleService.create(role).then(
       function () {
          toaster.pop({
            type: 'success',
            title: role.name,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: role.name,
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
