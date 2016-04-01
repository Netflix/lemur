'use strict';

angular.module('lemur')
  .controller('CertificateExportController', function ($scope, $modalInstance, CertificateApi, CertificateService, PluginService, FileSaver, Blob, toaster, editId) {
    CertificateApi.get(editId).then(function (certificate) {
      $scope.certificate = certificate;
    });

    PluginService.getByType('export').then(function (plugins) {
      $scope.plugins = plugins;
    });

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.save = function (certificate) {
      CertificateService.export(certificate).then(
        function (response) {
            var byteCharacters = atob(response.data);
            var byteArrays = [];

            for (var offset = 0; offset < byteCharacters.length; offset += 512) {
              var slice = byteCharacters.slice(offset, offset + 512);

              var byteNumbers = new Array(slice.length);
              for (var i = 0; i < slice.length; i++) {
                byteNumbers[i] = slice.charCodeAt(i);
              }

              var byteArray = new Uint8Array(byteNumbers);

              byteArrays.push(byteArray);
            }

          var blob = new Blob(byteArrays, {type: 'application/octet-stream'});
          FileSaver.saveAs(blob, certificate.name + '.' + response.extension);
          $scope.passphrase = response.passphrase;
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Failed to export ' + response.data.message,
            timeout: 100000
          });
        });
    };
  })
  .controller('CertificateEditController', function ($scope, $modalInstance, CertificateApi, CertificateService, DestinationService, NotificationService, toaster, editId) {
    CertificateApi.get(editId).then(function (certificate) {
      CertificateService.getNotifications(certificate);
      CertificateService.getDestinations(certificate);
      CertificateService.getReplacements(certificate);
      $scope.certificate = certificate;
    });

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.save = function (certificate) {
      CertificateService.update(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully updated!'
          });
          $modalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Failed to update ' + response.data.message,
            timeout: 100000
          });
        });
    };

    $scope.certificateService = CertificateService;
    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;
  })

  .controller('CertificateCreateController', function ($scope, $modalInstance, CertificateApi, CertificateService, DestinationService, AuthorityService, PluginService, MomentService, WizardHandler, LemurRestangular, NotificationService, toaster) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');

    // set the defaults
    CertificateService.getDefaults($scope.certificate);

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.create = function (certificate) {
      WizardHandler.wizard().context.loading = true;
      CertificateService.create(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully created!'
          });
          $modalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Was not created! ' + response.data.message,
            timeout: 100000
          });
          WizardHandler.wizard().context.loading = false;
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

    $scope.certificateService = CertificateService;
    $scope.authorityService = AuthorityService;
    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;
  });
