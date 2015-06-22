'use strict';

angular.module('lemur')
  .config(function config($routeProvider) {
    $routeProvider.when('/elbs', {
      templateUrl: '/angular/elbs/view/view.tpl.html',
      controller: 'ELBViewController'
    });
  })

  .controller('ELBViewController', function ($scope, ELBApi, ELBService, ngTableParams) {
    $scope.filter = {};
    $scope.elbsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        ELBApi.getList(params.url())
          .then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };
  });
