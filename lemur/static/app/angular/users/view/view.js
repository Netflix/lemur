'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('users', {
      url: '/users',
      templateUrl: '/angular/users/view/view.tpl.html',
      controller: 'UsersViewController'
    });
  })

  .controller('UsersViewController', function ($scope, $modal, UserApi, UserService, ngTableParams) {
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

    $scope.edit = function (userId) {
      var modalInstance = $modal.open({
        animation: true,
        templateUrl: '/angular/users/user/user.tpl.html',
        controller: 'UsersEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return userId;
          }
        }
      });

      modalInstance.result.then(function () {
        $scope.usersTable.reload();
      });

    };

    $scope.create = function () {
      var modalInstance = $modal.open({
        animation: true,
        controller: 'UsersCreateController',
        templateUrl: '/angular/users/user/user.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      modalInstance.result.then(function () {
        $scope.usersTable.reload();
      });

    };

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

  });
