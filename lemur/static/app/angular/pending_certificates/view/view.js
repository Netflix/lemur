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

    $scope.edit = function (pendingCertificateId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'PendingCertificateEditController',
        templateUrl: '/angular/pending_certificates/pending_certificate/edit.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return pendingCertificateId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.pendingCertificateTable.reload();
      });
    };

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

    $scope.cancel = function (pendingCertificateId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'PendingCertificateCancelController',
        templateUrl: '/angular/pending_certificates/pending_certificate/cancel.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          cancelId: function () {
            return pendingCertificateId;
          }
        }
      });
      uibModalInstance.result.then(function () {
        $scope.pendingCertificateTable.reload();
      });
    };

    $scope.upload = function (pendingCertificateId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'PendingCertificateUploadController',
        templateUrl: '/angular/pending_certificates/pending_certificate/upload.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          uploadId: function () {
            return pendingCertificateId;
          }
        }
      });
      uibModalInstance.result.then(function () {
        $scope.pendingCertificateTable.reload();
      });
    };

  });
