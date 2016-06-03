'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('users', {
      url: '/users',
      templateUrl: '/angular/users/view/view.tpl.html',
      controller: 'UsersViewController'
    });
  })

  .controller('UsersViewController', function ($scope, $uibModal, UserApi, UserService, ngTableParams) {
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
      var uibModalInstance = $uibModal.open({
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

      uibModalInstance.result.then(function () {
        $scope.usersTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'UsersCreateController',
        templateUrl: '/angular/users/user/user.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.usersTable.reload();
      });

    };

  });
