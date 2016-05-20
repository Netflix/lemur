'use strict';

angular.module('lemur')
.directive('roleSelect', function (RoleApi) {
    return {
      restrict: 'AE',
      scope: {
        ngModel: '='
      },
      replace: true,
      require: 'ngModel',
      templateUrl: '/angular/roles/role/roleSelect.tpl.html',
      link: function postLink($scope) {
        RoleApi.getList().then(function (roles) {
          $scope.roles = roles;
        });

        $scope.findRoleByName = function (search) {
          return RoleApi.getList({'filter[name]': search})
            .then(function (roles) {
              return roles;
            });
        };
      }
    };
  })
  .controller('RolesEditController', function ($scope, $uibModalInstance, RoleApi, RoleService, UserService, toaster, editId) {
    RoleApi.get(editId).then(function (role) {
      $scope.role = role;
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

    $scope.loadPassword = function (role) {
      RoleService.loadPassword(role).then(
        function (response) {
          $scope.role.password = response.password;
          $scope.role.username = response.username;
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
