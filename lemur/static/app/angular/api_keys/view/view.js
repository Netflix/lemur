'use strict';

angular.module('lemur')
  .config(function config($stateProvider) {
    $stateProvider.state('keys', {
      url: '/keys',
      templateUrl: '/angular/api_keys/view/view.tpl.html',
      controller: 'ApiKeysViewController'
    });
  })
  .controller('ApiKeysViewController', function ($scope, $uibModal, ApiKeyApi, ApiKeyService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.apiKeysTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        ApiKeyApi.getList(params.url()).then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.updateRevoked = function (apiKey) {
      ApiKeyService.update(apiKey).then(
        function () {
          toaster.pop({
            type: 'success',
            title: 'Updated JWT!',
            body: apiKey.jwt
          });
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: apiKey.name || 'Unnamed API Key',
            body: 'Unable to update! ' + response.data.message,
            timeout: 100000
          });
        });
    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'ApiKeysCreateController',
        templateUrl: '/angular/api_keys/api_key/api_key.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.apiKeysTable.reload();
      });

    };

    $scope.remove = function (apiKey) {
      apiKey.remove().then(
        function () {
            toaster.pop({
              type: 'success',
              title: 'Removed!',
              body: 'Deleted that API Key!'
            });
            $scope.apiKeysTable.reload();
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

    $scope.edit = function (apiKeyId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/api_keys/api_key/api_key.tpl.html',
        controller: 'ApiKeysEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
            editId: function () {
              return apiKeyId;
            }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.apiKeysTable.reload();
      });

    };

  });
