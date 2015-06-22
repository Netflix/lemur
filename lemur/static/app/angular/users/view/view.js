'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/users', {
      templateUrl: '/angular/users/view/view.tpl.html',
      controller: 'UsersViewController'
    });
  })

  .controller('UsersViewController', function ($scope, UserApi, UserService, ngTableParams) {
    $scope.filter = {};
    $scope.usersTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        UserApi.getList(params.url()).then(
          function (data) {
              params.total(data.total);
              $defer.resolve(data);
          }
        );
      }
    });

    $scope.remove = function (account) {
      account.remove().then(function () {
        $scope.usersTable.reload();
      });
    };

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

  });
