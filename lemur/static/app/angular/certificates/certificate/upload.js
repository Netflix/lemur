'use strict';

angular.module('lemur')

  .controller('CertificateUploadController', function ($scope, $modalInstance, CertificateService, LemurRestangular, DestinationService, ELBService, PluginService) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');
    $scope.upload = CertificateService.upload;

    $scope.destinationService = DestinationService;
    $scope.elbService = ELBService;

    PluginService.get('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.attachELB = function (elb) {
      $scope.certificate.attachELB(elb);
      ELBService.getListeners(elb).then(function (listeners) {
        $scope.certificate.elb.listeners = listeners;
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

  });
