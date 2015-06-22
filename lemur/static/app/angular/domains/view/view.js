'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/domains', {
      templateUrl: '/angular/domains/view/view.tpl.html',
      controller: 'DomainsViewController'
    });
  })

  .controller('DomainsViewController', function ($scope, DomainApi, ngTableParams) {
    $scope.filter = {};
    $scope.domainsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        DomainApi.getList().then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

  });
