'use strict';

angular.module('lemur')

  .controller('CertificateUploadController', function ($scope, $modalInstance, CertificateService, LemurRestangular, DestinationService, NotificationService, PluginService, toaster) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');
    $scope.upload = CertificateService.upload;

    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;

    PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (certificate) {
      CertificateService.upload(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully uploaded!'
          });
          $modalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Failed to upload ' + response.data.message,
            timeout: 100000
          });
        });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

  });
