'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/accounts', {
      templateUrl: '/angular/accounts/view/view.tpl.html',
      controller: 'AccountsViewController'
    });
  })

  .controller('AccountsViewController', function ($scope, AccountApi, AccountService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.accountsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        AccountApi.getList(params.url()).then(
          function (data) {
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });

    $scope.remove = function (account) {
      account.remove().then(
        function () {
            $scope.accountsTable.reload();
          },
          function (response) {
            toaster.pop({
              type: 'error',
              title: 'Opps',
              body: 'I see what you did there' + response.data.message
            });
          }
      );
    };

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

  });
