'use strict';

angular.module('lemur')

  .controller('CertificateUploadController', function ($scope, $modalInstance, CertificateService, LemurRestangular, DestinationService, NotificationService, PluginService) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');
    $scope.upload = CertificateService.upload;

    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;

    PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.save = function (certificate) {
      CertificateService.upload(certificate).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

  });
