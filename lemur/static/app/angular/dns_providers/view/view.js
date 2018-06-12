'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('dns_providers', {
      url: '/dns_providers',
      templateUrl: '/angular/dns_providers/view/view.tpl.html',
      controller: 'DnsProvidersViewController'
    });
  })

  .controller('DnsProvidersViewController', function ($scope, $uibModal, DnsProviderApi, DnsProviderService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.dnsProvidersTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        DnsProviderApi.getList(params.url()).then(
          function (data) {
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });

    $scope.remove = function (dns_provider) {
      dns_provider.remove().then(
        function () {
            $scope.dnsProvidersTable.reload();
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

    $scope.edit = function (dns_providerId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/dns_providers/dns_provider/dns_provider.tpl.html',
        controller: 'DnsProviderEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
            editId: function () {
              return dns_providerId;
            }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.dnsProvidersTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'DnsProviderCreateController',
        templateUrl: '/angular/dns_providers/dns_provider/dns_provider.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.dnsProvidersTable.reload();
      });

    };

  });
