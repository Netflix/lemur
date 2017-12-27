'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider
      .state('pending_certificates', {
        url: '/pending_certificates',
        templateUrl: '/angular/pending_certificates/view/view.tpl.html',
        controller: 'PendingCertificatesViewController'
      })
      .state('pending_certificate', {
        url: '/pending_certificates/:name',
        templateUrl: '/angular/pending_certificates/view/view.tpl.html',
        controller: 'PendingCertificatesViewController'
      });
  })

  .controller('PendingCertificatesViewController', function ($q, $scope, $uibModal, $stateParams, PendingCertificateApi, PendingCertificateService, ngTableParams, toaster) {
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

    $scope.loadPrivateKey = function (pendingCertificate) {
      if (pendingCertificate.privateKey !== undefined) {
        return;
      }

      PendingCertificateService.loadPrivateKey(pendingCertificate).then(
        function (response) {
          if (response.key === null) {
            toaster.pop({
              type: 'warning',
              title: pendingCertificate.name,
              body: 'No private key found!'
            });
          } else {
            pendingCertificate.privateKey = response.key;
          }
        },
        function () {
          toaster.pop({
            type: 'error',
            title: pendingCertificate.name,
            body: 'You do not have permission to view this key!',
            timeout: 100000
          });
        });
    };
  });
