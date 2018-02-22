'use strict';

angular.module('lemur')
.controller('PendingCertificateEditController', function ($scope, $uibModalInstance, PendingCertificateApi, PendingCertificateService, CertificateService, DestinationService, NotificationService, toaster, editId) {
  PendingCertificateApi.get(editId).then(function (pendingCertificate) {
    $scope.pendingCertificate = pendingCertificate;
  });

  $scope.cancel = function () {
    $uibModalInstance.dismiss('cancel');
  };

  $scope.save = function (pendingCertificate) {
    PendingCertificateService.update(pendingCertificate).then(
      function () {
        toaster.pop({
          type: 'success',
          title: pendingCertificate.name,
          body: 'Successfully updated!'
        });
        $uibModalInstance.close();
      },
      function (response) {
        toaster.pop({
          type: 'error',
          title: pendingCertificate.name,
          body: 'lemur-bad-request',
          bodyOutputType: 'directive',
          directiveData: response.data,
          timeout: 100000
        });
      });
  };

  $scope.pendingCertificateService = PendingCertificateService;
  $scope.certificateService = CertificateService;
  $scope.destinationService = DestinationService;
  $scope.notificationService = NotificationService;
})
.controller('PendingCertificateCancelController', function ($scope, $uibModalInstance, PendingCertificateApi, PendingCertificateService, toaster, cancelId) {
  PendingCertificateApi.get(cancelId).then(function (pendingCertificate) {
    $scope.pendingCertificate = pendingCertificate;
  });

  $scope.exit = function () {
    $uibModalInstance.dismiss('cancel');
  };

  $scope.cancel = function (pendingCertificate, cancelOptions) {
    PendingCertificateService.cancel(pendingCertificate, cancelOptions).then(
      function () {
        toaster.pop({
          type: 'success',
          title: pendingCertificate.name,
          body: 'Successfully cancelled pending certificate!'
        });
        $uibModalInstance.close();
      },
      function (response) {
        toaster.pop({
          type: 'error',
          title: pendingCertificate.name,
          body: 'lemur-bad-request',
          bodyOutputType: 'directive',
          directiveData: response.data,
          timeout: 100000
        });
      });
  };


});
