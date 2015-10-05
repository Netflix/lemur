'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('roles', {
      url: '/roles',
      templateUrl: '/angular/roles/view/view.tpl.html',
      controller: 'RolesViewController'
    });
  })

  .controller('RolesViewController', function ($scope, $modal, RoleApi, RoleService, ngTableParams) {
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

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };


    $scope.edit = function (roleId) {
      var modalInstance = $modal.open({
        animation: true,
        templateUrl: '/angular/roles/role/role.tpl.html',
        controller: 'RolesEditController',
        size: 'lg',
        resolve: {
          editId: function () {
            return roleId;
          }
        }
      });

      modalInstance.result.then(function () {
        $scope.rolesTable.reload();
      });

    };

    $scope.create = function () {
      var modalInstance = $modal.open({
        animation: true,
        controller: 'RolesCreateController',
        templateUrl: '/angular/roles/role/role.tpl.html',
        size: 'lg'
      });

      modalInstance.result.then(function () {
        $scope.rolesTable.reload();
      });

    };

  });
