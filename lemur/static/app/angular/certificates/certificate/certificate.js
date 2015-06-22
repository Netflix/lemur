'use strict';

angular.module('lemur')
  .config(function config($routeProvider) {
    $routeProvider.when('/certificates/create', {
      templateUrl: '/angular/certificates/certificate/certificateWizard.tpl.html',
      controller: 'CertificateCreateController'
    });

    $routeProvider.when('/certificates/:id/edit', {
      templateUrl: '/angular/certificates/certificate/edit.tpl.html',
      controller: 'CertificateEditController'
    });
  })

  .controller('CertificateEditController', function ($scope, $routeParams, CertificateApi, CertificateService, MomentService) {
    CertificateApi.get($routeParams.id).then(function (certificate) {
      $scope.certificate = certificate;
    });

    $scope.momentService = MomentService;
    $scope.save = CertificateService.update;

  })

  .controller('CertificateCreateController', function ($scope, $modal, CertificateApi, CertificateService, AccountService, ELBService, AuthorityService, MomentService, LemurRestangular) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');

    $scope.save = function (certificate) {
      var loadingModal = $modal.open({backdrop: 'static', template: '<wave-spinner></wave-spinner>', windowTemplateUrl: 'angular/loadingModal.html', size: 'large'});
      CertificateService.create(certificate).then(function (response) {
        loadingModal.close();
      });
    };

    $scope.templates = [
      {
        'name': 'Client Certificate',
        'description': '',
        'extensions': {
          'basicConstraints': {},
          'keyUsage': {
            'isCritical': true,
            'useDigitalSignature': true
          },
          'extendedKeyUsage': {
            'isCritical': true,
            'useClientAuthentication': true
          },
          'subjectKeyIdentifier': {
            'includeSKI': true
          }
        }
      },
      {
        'name': 'Server Certificate',
        'description': '',
        'extensions' : {
          'basicConstraints': {},
          'keyUsage': {
            'isCritical': true,
            'useKeyEncipherment': true,
            'useDigitalSignature': true
          },
          'extendedKeyUsage': {
            'isCritical': true,
            'useServerAuthentication': true
          },
          'subjectKeyIdentifier': {
            'includeSKI': true
          }
        }
      }
    ];

    $scope.openNotBefore = function($event) {
      $event.preventDefault();
      $event.stopPropagation();

      $scope.openNotBefore.isOpen = true;
    };

    $scope.openNotAfter = function($event) {
      $event.preventDefault();
      $event.stopPropagation();

      $scope.openNotAfter.isOpen = true;

    };

    $scope.elbService = ELBService;
    $scope.authorityService = AuthorityService;
    $scope.accountService = AccountService;
  });
