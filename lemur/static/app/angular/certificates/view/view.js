'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {

    $stateProvider
      .state('certificates', {
        url: '/certificates',
        templateUrl: '/angular/certificates/view/view.tpl.html',
        controller: 'CertificatesViewController'
      })
      .state('certificate', {
        url: '/certificates/:name',
        templateUrl: '/angular/certificates/view/view.tpl.html',
        controller: 'CertificatesViewController'
      });
  })

  .controller('CertificatesViewController', function ($q, $scope, $modal, $stateParams, CertificateApi, CertificateService, MomentService, ngTableParams, toaster) {
    $scope.filter = $stateParams;
    $scope.certificateTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        CertificateApi.getList(params.url())
          .then(function (data) {
            // TODO we should attempt to resolve all of these in parallel
            _.each(data, function (certificate) {
              CertificateService.getDomains(certificate);
              CertificateService.getDestinations(certificate);
              CertificateService.getNotifications(certificate);
              CertificateService.getReplacements(certificate);
              CertificateService.getAuthority(certificate);
              CertificateService.getCreator(certificate);
            });
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.momentService = MomentService;

    $scope.remove = function (certificate) {
      certificate.remove().then(
        function () {
          $scope.certificateTable.reload();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Unable to remove certificate! ' + response.data.message,
            timeout: 100000
          });
        });
    };

    $scope.loadPrivateKey = function (certificate) {
      CertificateService.loadPrivateKey(certificate).then(
        function (response) {
          if (response.key === null) {
            toaster.pop({
              type: 'warning',
              title: certificate.name,
              body: 'No private key found!'
            });
          } else {
            certificate.privateKey = response.key;
          }
        },
        function () {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'You do not have permission to view this key!',
            timeout: 100000
          });
        });
    };

    $scope.updateActive = function (certificate) {
      CertificateService.updateActive(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Updated!'
          });
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Unable to update! ' + response.data.message,
            timeout: 100000
          });
          certificate.active = false;
        });
    };
    $scope.getCertificateStatus = function () {
      var def = $q.defer();
      def.resolve([{'title': 'Active', 'id': true}, {'title': 'Inactive', 'id': false}]);
      return def;
    };

    $scope.show = {title: 'Current User', value: 'currentUser'};

    $scope.fields = [{title: 'Current User', value: 'currentUser'}, {title: 'All', value: 'all'}];


    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

    $scope.create = function () {
      var modalInstance = $modal.open({
        animation: true,
        controller: 'CertificateCreateController',
        templateUrl: '/angular/certificates/certificate/certificateWizard.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      modalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.edit = function (certificateId) {
      var modalInstance = $modal.open({
        animation: true,
        controller: 'CertificateEditController',
        templateUrl: '/angular/certificates/certificate/edit.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return certificateId;
          }
        }
      });

      modalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.import = function () {
      var modalInstance = $modal.open({
        animation: true,
        controller: 'CertificateUploadController',
        templateUrl: '/angular/certificates/certificate/upload.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      modalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.export = function (certificateId) {
      $modal.open({
        animation: true,
        controller: 'CertificateExportController',
        templateUrl: '/angular/certificates/certificate/export.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return certificateId;
          }
        }
      });
    };
  });
