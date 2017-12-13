'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider
      .state('pending_certificates', {
        url: '/pending_certificates',
        templateUrl: '/angular/pending_certificates/view/view.tpl.html',
        controller: 'PendingCertificatesViewController'
      });
  })

  .controller('PendingCertificatesViewController', function ($q, $scope, $uibModal, $stateParams, PendingCertificateApi, PendingCertificateService, ngTableParams) {
    $scope.filter = $stateParams;
    $scope.pendingCertificateTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        PendingCertificateApi.getList(params.url())
          .then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });
  });
