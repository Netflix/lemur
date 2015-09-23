'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/certificates', {
      templateUrl: '/angular/certificates/view/view.tpl.html',
      controller: 'CertificatesViewController'
    });
  })

  .controller('CertificatesViewController', function ($q, $scope, $modal, CertificateApi, CertificateService, MomentService, ngTableParams) {
    $scope.filter = {};
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
              CertificateService.getAuthority(certificate);
              CertificateService.getCreator(certificate);
            });
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.certificateService = CertificateService;
    $scope.momentService = MomentService;

    $scope.remove = function (certificate) {
      certificate.remove().then(function () {
        $scope.certificateTable.reload();
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
        size: 'lg'
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
        size: 'lg'
      });

      modalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };
  });
