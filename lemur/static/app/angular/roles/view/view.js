'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('roles', {
      url: '/roles',
      templateUrl: '/angular/roles/view/view.tpl.html',
      controller: 'RolesViewController'
    });
  })

  .controller('RolesViewController', function ($scope, $uibModal, RoleApi, RoleService, ngTableParams) {
    $scope.filter = {};
    $scope.rolesTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        RoleApi.getList(params.url())
          .then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.remove = function (role) {
      RoleService.remove(role).then(function () {
        $scope.rolesTable.reload();
      });
    };

    $scope.edit = function (roleId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/roles/role/role.tpl.html',
        controller: 'RolesEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return roleId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.rolesTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'RolesCreateController',
        templateUrl: '/angular/roles/role/role.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.rolesTable.reload();
      });

    };

  });
