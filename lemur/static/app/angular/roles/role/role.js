'use strict';

angular.module('lemur')

  .controller('RolesEditController', function ($scope, $uibModalInstance, RoleApi, RoleService, UserService, editId) {
    RoleApi.get(editId).then(function (role) {
      $scope.role = role;
      RoleService.getUsers(role);
    });

    $scope.save = function (role) {
      RoleService.update(role).then(function () {
        $uibModalInstance.close();
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

  .controller('RolesCreateController', function ($scope,$uibModalInstance, RoleApi, RoleService, UserService, LemurRestangular) {
    $scope.role = LemurRestangular.restangularizeElement(null, {}, 'roles');
    $scope.userService = UserService;

    $scope.save = function (role) {
      RoleService.create(role).then(function () {
        $uibModalInstance.close();
      });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };
  });
