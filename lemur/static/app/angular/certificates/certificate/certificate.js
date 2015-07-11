'use strict';

angular.module('lemur')
  .controller('CertificateEditController', function ($scope, $routeParams, CertificateApi, CertificateService, MomentService) {
    CertificateApi.get($routeParams.id).then(function (certificate) {
      $scope.certificate = certificate;
    });

    $scope.momentService = MomentService;
    $scope.save = CertificateService.update;

  })

  .controller('CertificateCreateController', function ($scope, $modalInstance, CertificateApi, CertificateService, DestinationService, ELBService, AuthorityService, PluginService, MomentService, WizardHandler, LemurRestangular) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');

    $scope.create = function (certificate) {
      WizardHandler.wizard().context.loading = true;
      CertificateService.create(certificate).then(function (response) {
        WizardHandler.wizard().context.loading = false;
        $modalInstance.close();
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

    PluginService.get('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.elbService = ELBService;
    $scope.authorityService = AuthorityService;
    $scope.destinationService = DestinationService;
  });
