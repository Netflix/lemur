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
        url: '/certificates/:fixedName', // use "fixedName" if in URL to indicate 'like' query can be avoided
        templateUrl: '/angular/certificates/view/view.tpl.html',
        controller: 'CertificatesViewController'
      });
  })

  .controller('CertificatesViewController', function ($q, $scope, $uibModal, $stateParams, CertificateApi, CertificateService, MomentService, ngTableParams, toaster) {
    $scope.filter = $stateParams;
    $scope.expiredText = ['Show Expired', 'Hide Expired'];
    $scope.expiredValue = 0;
    $scope.expiresInDays = 0;
    $scope.expiredButton = $scope.expiredText[$scope.expiredValue];
    $scope.certificateTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      short: true,
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        const url = params.url();
        if (url['filter[Not%20Before%20From]'] || url['filter[Not%20Before%20To]']) {
            const from = url['filter[Not%20Before%20From]']?url['filter[Not%20Before%20From]'].toISOString().substr(0,10): '*';
            const to = url['filter[Not%20Before%20To]']?url['filter[Not%20Before%20To]'].toISOString().substr(0,10): '*';
            delete url['filter[Not%20Before%20From]'];
            delete url['filter[Not%20Before%20To]'];
            url['filter[notBeforeRange]'] = from + 'to' + to;
        }
        if (url['filter[Not%20After%20From]'] || url['filter[Not%20After%20To]']) {
            const from = url['filter[Not%20After%20From]']?url['filter[Not%20After%20From]'].toISOString().substr(0,10): '*';
            const to = url['filter[Not%20After%20To]']?url['filter[Not%20After%20To]'].toISOString().substr(0,10): '*';
            delete url['filter[Not%20After%20From]'];
            delete url['filter[Not%20After%20To]'];
            url['filter[notAfterRange]'] = from + 'to' + to;
        }
        CertificateApi.getList(url)
          .then(function (data) {
            params.total(data.total);
            $defer.resolve(data);
          });
      }
    });

    $scope.showExpired = function (days = 0) {
      if ($scope.expiresInDays === days) {
        $scope.expiresInDays = 0;
      } else {
        $scope.expiresInDays = days;
        $scope.expiredValue = 0;
      }
      if (days === 0) {
        if ($scope.expiredValue === 0) {
          $scope.expiredValue = 1;
        }
        else {
          $scope.expiredValue = 0;
        }
        $scope.expiredButton = $scope.expiredText[$scope.expiredValue];
      }
      $scope.certificateTable = new ngTableParams({
        page: 1,            // show first page
        count: 10,          // count per page
        sorting: {
          id: 'desc'     // initial sorting
        },
        short: true,
        filter: $scope.filter
      }, {
        getData: function ($defer, params) {
          $scope.temp = angular.copy(params.url());
          if ($scope.temp['filter[Not%20Before%20From]'] || $scope.temp['filter[Not%20Before%20To]']) {
              const from = $scope.temp['filter[Not%20Before%20From]']?$scope.temp['filter[Not%20Before%20From]'].toISOString().substr(0,10): '*';
              const to = $scope.temp['filter[Not%20Before%20To]']?$scope.temp['filter[Not%20Before%20To]'].toISOString().substr(0,10): '*';
              delete $scope.temp['filter[Not%20Before%20From]'];
              delete $scope.temp['filter[Not%20Before%20To]'];
              $scope.temp['filter[notBeforeRange]'] = from + 'to' + to;
          }
          if ($scope.temp['filter[Not%20After%20From]'] || $scope.temp['filter[Not%20After%20To]']) {
              const from = $scope.temp['filter[Not%20After%20From]']?$scope.temp['filter[Not%20After%20From]'].toISOString().substr(0,10): '*';
              const to = $scope.temp['filter[Not%20After%20To]']?$scope.temp['filter[Not%20After%20To]'].toISOString().substr(0,10): '*';
              delete $scope.temp['filter[Not%20After%20From]'];
              delete $scope.temp['filter[Not%20After%20To]'];
              $scope.temp['filter[notAfterRange]'] = from + 'to' + to;
          }
          $scope.temp.showExpired = $scope.expiredValue;
          if ($scope.expiresInDays !== 0) {
            const now = new Date();
            const from = now.toISOString().substr(0,10);
            now.setDate(now.getDate() + $scope.expiresInDays);
            const to = now.toISOString().substr(0,10);
            if ($scope.expiresInDays > 0) {
              $scope.temp['filter[notAfterRange]'] = `${from}to${to}`;
            } else {
              $scope.temp['filter[notAfterRange]'] =  `${to}to${from}`;
              $scope.temp.showExpired = 1;
            }
          }
          CertificateApi.getList($scope.temp)
            .then(function (data) {
              params.total(data.total);
              $defer.resolve(data);
            });
        }
      });
    };

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
      if (certificate.privateKey !== undefined) {
        return;
      }

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

    $scope.updateNotify = function (certificate) {
      CertificateService.updateNotify(certificate).then(
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
          certificate.notify = false;
        });
    };
    $scope.getCertificateStatus = function () {
      var def = $q.defer();
      def.resolve([{'title': 'True', 'id': true}, {'title': 'False', 'id': false}]);
      return def;
    };

    $scope.show = {title: 'Current User', value: 'currentUser'};

    $scope.fields = [{title: 'Current User', value: 'currentUser'}, {title: 'All', value: 'all'}];

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'CertificateCreateController',
        templateUrl: '/angular/certificates/certificate/certificateWizard.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.clone = function (certificateId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'CertificateCloneController',
        templateUrl: '/angular/certificates/certificate/certificateWizard.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return certificateId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.edit = function (certificateId) {
      var uibModalInstance = $uibModal.open({
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

      uibModalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.import = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'CertificateUploadController',
        templateUrl: '/angular/certificates/certificate/upload.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.certificateTable.reload();
      });
    };

    $scope.export = function (certificateId) {
      $uibModal.open({
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

     $scope.revoke = function (certificate) {
      $uibModal.open({
        animation: true,
        controller: 'CertificateRevokeController',
        templateUrl: '/angular/certificates/certificate/revoke.tpl.html',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          certificates: function () {
            return [certificate];
          }
        }
      });
    };
    $scope.bulkActionEnabled = false;
    $scope.showSubMenu = false;

    $scope.revokeBulk = function () {
      if ($scope.multiList.length === 0) {
        toaster.pop({
          type: 'error',
          title: 'Please Select certificates to revoke using left side checkboxs',
          body: 'lemur-bad-request',
          bodyOutputType: 'directive',
          timeout: 100000
        });
      } else {
        $uibModal.open({
          animation: true,
          controller: 'CertificateRevokeController',
          templateUrl: '/angular/certificates/certificate/revoke.tpl.html',
          size: 'lg',
          backdrop: 'static',
          resolve: {
            certificates: function () {
              return $scope.multiList;
            }
          }
        });
      }
    };
    $scope.tiggleBulkAction = function (show) {
      $scope.multiList=[];
      if (show) {
        $scope.showSubMenu = !$scope.showSubMenu;
        $scope.bulkActionEnabled = true;
      } else {
        $scope.bulkActionEnabled = false;
        $scope.showSubMenu = false;
      }
    };
    $scope.toggleMultiListSelection = function toggleMultiListSelection(certificate) {
      const multiList = $scope.multiList.filter(cert => cert.id !== certificate.id);
      if (multiList.length === $scope.multiList.length) {
        multiList.push(certificate);
      }
      $scope.multiList = multiList;
    };
  });
