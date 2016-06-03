'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('sources', {
      url: '/sources',
      templateUrl: '/angular/sources/view/view.tpl.html',
      controller: 'SourcesViewController'
    });
  })

  .controller('SourcesViewController', function ($scope, $uibModal, SourceApi, SourceService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.sourcesTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        SourceApi.getList(params.url()).then(
          function (data) {
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });

    $scope.remove = function (source) {
      source.remove().then(
        function () {
            $scope.sourcesTable.reload();
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

    $scope.edit = function (sourceId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/sources/source/source.tpl.html',
        controller: 'SourcesEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
            editId: function () {
              return sourceId;
            }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.sourcesTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'SourcesCreateController',
        templateUrl: '/angular/sources/source/source.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.sourcesTable.reload();
      });

    };

  });
