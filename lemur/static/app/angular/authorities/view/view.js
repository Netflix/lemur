'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/authorities', {
      templateUrl: '/angular/authorities/view/view.tpl.html',
      controller: 'AuthoritiesViewController'
    });
  })

  .controller('AuthoritiesViewController', function ($scope, $q, AuthorityApi, AuthorityService, ngTableParams) {
    $scope.filter = {};
    $scope.authoritiesTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        AuthorityApi.getList(params.url()).then(function (data) {
          _.each(data, function(authority) {
            AuthorityService.getRoles(authority);
          });
          params.total(data.total);
          $defer.resolve(data);
        });
      }
    });

    $scope.authorityService = AuthorityService;

    $scope.getAuthorityStatus = function () {
      var def = $q.defer();
      def.resolve([{'title': 'Active', 'id': true}, {'title': 'Inactive', 'id': false}])
      return def;
    };

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

  });
