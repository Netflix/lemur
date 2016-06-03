'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('destinations', {
      url: '/destinations',
      templateUrl: '/angular/destinations/view/view.tpl.html',
      controller: 'DestinationsViewController'
    });
  })

  .controller('DestinationsViewController', function ($scope, $uibModal, DestinationApi, DestinationService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.destinationsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        DestinationApi.getList(params.url()).then(
          function (data) {
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });

    $scope.remove = function (destination) {
      destination.remove().then(
        function () {
            $scope.destinationsTable.reload();
          },
          function (response) {
            toaster.pop({
              type: 'error',
              title: 'Opps',
              body: 'I see what you did there: ' + response.data.message
            });
          }
      );
    };

    $scope.edit = function (destinationId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/destinations/destination/destination.tpl.html',
        controller: 'DestinationsEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
            editId: function () {
              return destinationId;
            }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.destinationsTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'DestinationsCreateController',
        templateUrl: '/angular/destinations/destination/destination.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.destinationsTable.reload();
      });

    };

  });
