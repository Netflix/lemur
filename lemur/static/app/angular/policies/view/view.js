'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('polices', {
      url: '/polices',
      templateUrl: '/angular/policies/view/view.tpl.html',
      controller: 'PolicesViewController'
    });
  })

  .controller('PolicesViewController', function ($scope, $uibModal, PolicesApi, PolicesService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.policesTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        PolicesApi.getList(params.url()).then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.updateSensitive = function (polices) {
      PolicesService.updateSensitive(polices).then(
        function () {
          toaster.pop({
            type: 'success',
            title: polices.name,
            body: 'Updated!'
          });
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: polices.name,
            body: 'Unable to update! ' + response.data.message,
            timeout: 100000
          });
          polices.sensitive = !polices.sensitive;
        });
    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'PolicesCreateController',
        templateUrl: '/angular/policies/domain/police.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.policesTable.reload();
      });

    };

    $scope.remove = function (police) {
      police.remove().then(
        function () {
            $scope.policesTable.reload();
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

    $scope.edit = function (policeId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/policies/domain/police.tpl.html',
        controller: 'PolicesEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
            editId: function () {
              return policeId;
            }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.policesTable.reload();
      });

    };

  });