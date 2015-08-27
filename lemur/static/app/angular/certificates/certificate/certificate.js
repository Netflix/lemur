'use strict';

angular.module('lemur')
  .controller('CertificateEditController', function ($scope, $modalInstance, CertificateApi, CertificateService, DestinationService, NotificationService, editId) {
    CertificateApi.get(editId).then(function (certificate) {
      CertificateService.getNotifications(certificate);
      CertificateService.getDestinations(certificate);
      $scope.certificate = certificate;
    });

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.save = function (certificate) {
      CertificateService.update(certificate).then(function () {
        $modalInstance.close();
      });
    };

    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;
  })

  .controller('CertificateCreateController', function ($scope, $modalInstance, CertificateApi, CertificateService, DestinationService, AuthorityService, PluginService, MomentService, WizardHandler, LemurRestangular, NotificationService) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');

    // set the defaults
    CertificateService.getDefaults($scope.certificate);

    $scope.create = function (certificate) {
      WizardHandler.wizard().context.loading = true;
      CertificateService.create(certificate).then(function () {
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

    PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.authorityService = AuthorityService;
    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;
  });
