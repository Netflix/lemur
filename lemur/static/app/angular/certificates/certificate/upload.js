'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/certificates/upload', {
      templateUrl: '/angular/certificates/certificate/upload.tpl.html',
      controller: 'CertificatesUploadController'
    });
  })

  .controller('CertificatesUploadController', function ($scope, CertificateService, LemurRestangular, AccountService, ELBService) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');
    $scope.upload = CertificateService.upload;

    $scope.accountService = AccountService;
    $scope.elbService = ELBService;


    $scope.attachELB = function (elb) {
      $scope.certificate.attachELB(elb);
      ELBService.getListeners(elb).then(function (listeners) {
        $scope.certificate.elb.listeners = listeners;
      });
    };
  });
