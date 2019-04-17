'use strict';

angular.module('lemur')
    .controller('PendingCertificateUploadController', function ($scope, $uibModalInstance, PendingCertificateApi, PendingCertificateService, toaster, uploadId) {
    PendingCertificateApi.get(uploadId).then(function (pendingCertificate) {
      $scope.pendingCertificate = pendingCertificate;
    });

    $scope.upload = PendingCertificateService.upload;
    $scope.save = function (pendingCertificate) {
      PendingCertificateService.upload(pendingCertificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: pendingCertificate.name,
            body: 'Successfully uploaded!'
          });
          $uibModalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: pendingCertificate.name,
            body: 'Failed to upload ' + response.data.message,
            timeout: 100000
          });
        });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };

  });
