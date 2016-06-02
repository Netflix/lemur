'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('endpoints', {
      url: '/endpoints',
      templateUrl: '/angular/endpoints/view/view.tpl.html',
      controller: 'EndpointsViewController'
    });
  })

  .controller('EndpointsViewController', function ($q, $scope, $uibModal, EndpointApi, EndpointService, MomentService, ngTableParams) {
    $scope.filter = {};
    $scope.endpointsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        EndpointApi.getList(params.url()).then(
          function (data) {
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

    $scope.momentService = MomentService;

    $scope.endpointService = EndpointService;

  });
