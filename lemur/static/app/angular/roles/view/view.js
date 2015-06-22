'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/roles', {
      templateUrl: '/angular/roles/view/view.tpl.html',
      controller: 'RolesViewController'
    });
  })

  .controller('RolesViewController', function ($scope, RoleApi, RoleService, ngTableParams) {
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

  });
