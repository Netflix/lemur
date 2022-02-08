'use strict';

angular.module('lemur')
  .controller('CertificateExportController', function ($scope, $uibModalInstance, CertificateApi, CertificateService, PluginService, FileSaver, Blob, toaster, editId) {
    CertificateApi.get(editId).then(function (certificate) {
      $scope.certificate = certificate;
    });

    PluginService.getByType('export').then(function (plugins) {
      $scope.plugins = plugins;
    });

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
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
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });
        });
    };
  })
  .controller('CertificateEditController', function ($scope, $uibModalInstance, CertificateApi, CertificateService, DestinationService, NotificationService, toaster, editId) {
    CertificateApi.get(editId).then(function (certificate) {
      $scope.certificate = certificate;
    });

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };

    $scope.save = function (certificate) {
      CertificateService.update(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully updated!'
          });
          $uibModalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });
        });
    };

    $scope.certificateService = CertificateService;
    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;
  })

  .controller('CertificateCreateController', function ($scope, $uibModalInstance, CertificateApi, CertificateService, DestinationService, AuthorityService, AuthorityApi, PluginService, MomentService, WizardHandler, LemurRestangular, NotificationService, toaster) {
    $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');
    // set the defaults
    CertificateService.getDefaults($scope.certificate);

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };

    $scope.getAuthoritiesByName = function (value) {
      return AuthorityService.findActiveAuthorityByName(value).then(function (authorities) {
        $scope.authorities = authorities;
      });
    };

    $scope.dateOptions = {
      formatYear: 'yy',
      maxDate: new Date(2020, 5, 22),
      minDate: new Date(),
      startingDay: 1
    };

    $scope.open1 = function() {
      $scope.popup1.opened = true;
    };

    $scope.open2 = function() {
      $scope.popup2.opened = true;
    };

    $scope.formats = ['dd-MMMM-yyyy', 'yyyy/MM/dd', 'dd.MM.yyyy', 'shortDate'];
    $scope.format = $scope.formats[0];
    $scope.altInputFormats = ['M!/d!/yyyy'];

    $scope.popup1 = {
      opened: false
    };

    $scope.popup2 = {
      opened: false
    };

    $scope.clearDatesAndDefaultValidity = function () {
      $scope.clearDates();
      $scope.certificate.validityType = 'defaultDays';
    };

    $scope.clearDates = function () {
      $scope.certificate.validityStart = null;
      $scope.certificate.validityEnd = null;
      $scope.certificate.validityYears = null;
    };

    CertificateService.getDnsProviders().then(function (providers) {
            $scope.dnsProviders = providers;
        }
    );

    $scope.create = function (certificate) {
      if(certificate.validityType === 'customDates' &&
          (!certificate.validityStart || !certificate.validityEnd)) { // these are not mandatory fields in schema, thus handling validation in js
          return showMissingDateError();
      }
      if(certificate.validityType === 'defaultDays' && $scope.certificate.authority.plugin.slug !== 'acme-issuer') {
        populateValidityDateAsPerDefault(certificate);
      }

      WizardHandler.wizard().context.loading = true;
      CertificateService.create(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully created!'
          });
          $uibModalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });

          WizardHandler.wizard().context.loading = false;
        });
    };

    function showMissingDateError() {
      let error = {};
      error.message = '';
      error.reasons = {};
      error.reasons.validityRange = 'Valid start and end dates are needed, else select Default option';

      toaster.pop({
        type: 'error',
        title: 'Validation Error',
        body: 'lemur-bad-request',
        bodyOutputType: 'directive',
        directiveData: error,
        timeout: 100000
      });
    }

    function populateValidityDateAsPerDefault(certificate) {
      // calculate start and end date as per default validity
      let startDate = new Date(), endDate = new Date();
      endDate.setDate(startDate.getDate() + certificate.authority.defaultValidityDays);
      certificate.validityStart = startDate;
      certificate.validityEnd = endDate;
    }

    $scope.templates = [
      {
        'name': 'Client Certificate',
        'description': '',
        'extensions': {
          'basicConstraints': {},
          'keyUsage': {
            'useDigitalSignature': true
          },
          'extendedKeyUsage': {
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
            'useKeyEncipherment': true,
            'useDigitalSignature': true
          },
          'extendedKeyUsage': {
            'useServerAuthentication': true
          },
          'subjectKeyIdentifier': {
            'includeSKI': true
          }
        }
      }
    ];


    PluginService.getByType('destination').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.certificateService = CertificateService;
    $scope.authorityService = AuthorityService;
    $scope.destinationService = DestinationService;
    $scope.notificationService = NotificationService;
  })

.controller('CertificateCloneController', function ($scope, $uibModalInstance, CertificateApi, CertificateService, DestinationService, AuthorityService, AuthorityApi, PluginService, MomentService, WizardHandler, LemurRestangular, NotificationService, toaster, editId) {
  $scope.certificate = LemurRestangular.restangularizeElement(null, {}, 'certificates');
  CertificateApi.get(editId).then(function (certificate) {
    $scope.certificate = certificate;
    // prepare the certificate for cloning
    $scope.certificate.name = ''; // we should prefer the generated name
    $scope.certificate.csr = null;  // should not clone CSR in case other settings are changed in clone
    $scope.certificate.validityStart = null;
    $scope.certificate.validityEnd = null;
    $scope.certificate.description = 'Cloning from cert ID ' + editId;
    $scope.certificate.replacedBy = []; // should not clone 'replaced by' info
    $scope.certificate.removeReplaces(); // should not clone 'replacement cert' info

    CertificateService.getDefaults($scope.certificate);
  });

  $scope.cancel = function () {
    $uibModalInstance.dismiss('cancel');
  };

  $scope.getAuthoritiesByName = function (value) {
    return AuthorityService.findAuthorityByName(value).then(function (authorities) {
      $scope.authorities = authorities;
    });
  };

  $scope.dateOptions = {
    formatYear: 'yy',
    maxDate: new Date(2020, 5, 22),
    minDate: new Date(),
    startingDay: 1
  };


  $scope.open1 = function() {
    $scope.popup1.opened = true;
  };

  $scope.open2 = function() {
    $scope.popup2.opened = true;
  };

  $scope.formats = ['dd-MMMM-yyyy', 'yyyy/MM/dd', 'dd.MM.yyyy', 'shortDate'];
  $scope.format = $scope.formats[0];
  $scope.altInputFormats = ['M!/d!/yyyy'];

  $scope.popup1 = {
    opened: false
  };

  $scope.popup2 = {
    opened: false
  };

  CertificateService.getDnsProviders().then(function (providers) {
            $scope.dnsProviders = providers;
        }
    );

  $scope.clearDates = function () {
    $scope.certificate.validityStart = null;
    $scope.certificate.validityEnd = null;
    $scope.certificate.validityYears = null;
  };

  $scope.create = function (certificate) {
     if(certificate.validityType === 'customDates' &&
          (!certificate.validityStart || !certificate.validityEnd)) { // these are not mandatory fields in schema, thus handling validation in js
          return showMissingDateError();
     }
     if(certificate.validityType === 'defaultDays' && $scope.certificate.authority.plugin.slug !== 'acme-issuer') {
        populateValidityDateAsPerDefault(certificate);
     }

    WizardHandler.wizard().context.loading = true;
    CertificateService.create(certificate).then(
      function () {
        toaster.pop({
          type: 'success',
          title: certificate.name,
          body: 'Successfully created!'
        });
        $uibModalInstance.close();
      },
      function (response) {
        toaster.pop({
          type: 'error',
          title: certificate.name,
          body: 'lemur-bad-request',
          bodyOutputType: 'directive',
          directiveData: response.data,
          timeout: 100000
        });

        WizardHandler.wizard().context.loading = false;
      });
  };

  function showMissingDateError() {
      let error = {};
      error.message = '';
      error.reasons = {};
      error.reasons.validityRange = 'Valid start and end dates are needed, else select Default option';

      toaster.pop({
        type: 'error',
        title: 'Validation Error',
        body: 'lemur-bad-request',
        bodyOutputType: 'directive',
        directiveData: error,
        timeout: 100000
      });
    }

    function populateValidityDateAsPerDefault(certificate) {
      // calculate start and end date as per default validity
      let startDate = new Date(), endDate = new Date();
      endDate.setDate(startDate.getDate() + certificate.authority.defaultValidityDays);
      certificate.validityStart = startDate;
      certificate.validityEnd = endDate;
    }

  $scope.templates = [
    {
      'name': 'Client Certificate',
      'description': '',
      'extensions': {
        'basicConstraints': {},
        'keyUsage': {
          'useDigitalSignature': true
        },
        'extendedKeyUsage': {
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
          'useKeyEncipherment': true,
          'useDigitalSignature': true
        },
        'extendedKeyUsage': {
          'useServerAuthentication': true
        },
        'subjectKeyIdentifier': {
          'includeSKI': true
        }
      }
    }
  ];

  PluginService.getByType('destination').then(function (plugins) {
    $scope.plugins = plugins;
  });

  $scope.certificateService = CertificateService;
  $scope.authorityService = AuthorityService;
  $scope.destinationService = DestinationService;
  $scope.notificationService = NotificationService;
})

.controller('CertificateRevokeController', function ($scope, $uibModalInstance, CertificateApi, CertificateService, LemurRestangular, NotificationService, toaster, revokeId) {
  CertificateApi.get(revokeId).then(function (certificate) {
    $scope.certificate = certificate;
  });

  $scope.cancel = function () {
    $uibModalInstance.dismiss('cancel');
  };

  $scope.revoke = function (certificate, crlReason) {
   CertificateService.revoke(certificate, crlReason).then(
      function () {
        toaster.pop({
          type: 'success',
          title: certificate.name,
          body: 'Successfully revoked!'
        });
        $uibModalInstance.close();
      },
      function (response) {
        toaster.pop({
          type: 'error',
          title: certificate.name,
          body: 'lemur-bad-request',
          bodyOutputType: 'directive',
          directiveData: response.data,
          timeout: 100000
        });
      });
  };
})
.controller('CertificateInfoController', function ($scope, CertificateApi) {
  $scope.fetchFullCertificate = function (certId) {
    CertificateApi.get(certId).then(function (certificate) {
      $scope.certificate = certificate;
    });
  };
})
;
