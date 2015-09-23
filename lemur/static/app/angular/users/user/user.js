'use strict';

angular.module('lemur')

  .controller('UsersEditController', function ($scope, $modalInstance, UserApi, UserService, RoleService, editId) {
    UserApi.get(editId).then(function (user) {
      UserService.getRoles(user);
      $scope.user = user;
    });

    $scope.save = UserService.update;
    $scope.roleService = RoleService;

    $scope.rolePage = 1;


    $scope.save = function (user) {
      UserService.update(user).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.loadMoreRoles = function () {
      $scope.rolePage += 1;
      UserService.loadMoreRoles($scope.user, $scope.rolePage);
    };
  })

  .controller('UsersCreateController', function ($scope, $modalInstance, UserService, LemurRestangular, RoleService) {
    $scope.user = LemurRestangular.restangularizeElement(null, {}, 'users');
    $scope.save = UserService.create;
    $scope.roleService = RoleService;

    $scope.create = function (user) {
      UserService.create(user).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

  });
