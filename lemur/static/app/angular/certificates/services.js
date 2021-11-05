'use strict';

angular.module('lemur')
  .service('CertificateApi', function (LemurRestangular, DomainService) {
    LemurRestangular.extendModel('certificates', function (obj) {
      return angular.extend(obj, {
        attachRole: function (role) {
          this.selectedRole = null;
          if (this.roles === undefined) {
            this.roles = [];
          }
          this.roles.push(role);
        },
        removeRole: function (index) {
          this.roles.splice(index, 1);
        },
        attachAuthority: function (authority) {
          this.authority = authority;
          this.authority.maxDate = moment(this.authority.notAfter).subtract(1, 'days').format('YYYY/MM/DD');
        },
        attachCommonName: function () {
          if (this.extensions === undefined) {
            this.extensions = {};
          }

          if (this.extensions.subAltNames === undefined) {
            this.extensions.subAltNames = {'names': []};
          }

          if (angular.isString(this.commonName)) {
            this.extensions.subAltNames.names.unshift({'nameType': 'DNSName', 'value': this.commonName});
          }
        },
        removeCommonName: function () {
          if (angular.isDefined(this.extensions) && angular.isDefined(this.extensions.subAltNames)) {
            if (angular.equals(this.extensions.subAltNames.names[0].value, this.commonName)) {
              this.extensions.subAltNames.names.shift();
            }
          }
        },
        attachSubAltName: function (form) {
          if (this.extensions === undefined) {
            this.extensions = {};
          }

          if (this.extensions.subAltNames === undefined) {
            this.extensions.subAltNames = {'names': []};
          }

          if (!angular.isString(this.subAltType)) {
            this.subAltType = 'DNSName';
          }

          if (angular.isString(this.subAltValue) && angular.isString(this.subAltType)) {
            this.extensions.subAltNames.names.push({'nameType': this.subAltType, 'value': this.subAltValue});
          }

          if (angular.isDefined(form)) {
            // adding SAN makes CN optional
            form.commonName.$setValidity('required', null);
          }

          this.subAltType = null;
          this.subAltValue = null;
        },
        removeSubAltName: function (form, index) {
          this.extensions.subAltNames.names.splice(index, 1);

          let isSanPresent = this.extensions.subAltNames.names.length > 0;
          if (!isSanPresent) {
            let commonName = form.commonName.$viewValue;
            form.commonName.$setValidity('required', angular.isDefined(commonName) && commonName !== '');
          }
        },
        checkCommonNameOptional: function (form) {
           if (angular.isDefined(this.extensions) && angular.isDefined(this.extensions.subAltNames)) {
             let isSanPresent = this.extensions.subAltNames.names.length > 0;
             if (isSanPresent) {
                form.commonName.$setValidity('required', true);
              }
           }
        },
        attachCustom: function () {
          if (this.extensions === undefined) {
            this.extensions = {};
          }

          if (this.extensions.custom === undefined) {
            this.extensions.custom = [];
          }

          if (angular.isString(this.customOid) && angular.isString(this.customEncoding) && angular.isString(this.customValue)) {
            this.extensions.custom.push(
              {
                'oid': this.customOid,
                'isCritical': this.customIsCritical || false,
                'encoding': this.customEncoding,
                'value': this.customValue
              }
            );
          }

          this.customOid = null;
          this.customIsCritical = null;
          this.customEncoding = null;
          this.customValue = null;
        },
        removeCustom: function (index) {
          this.extensions.custom.splice(index, 1);
        },
        attachDestination: function (destination) {
          this.selectedDestination = null;
          if (this.destinations === undefined) {
            this.destinations = [];
          }
          this.destinations.push(destination);
        },
        removeDestination: function (index) {
          this.destinations.splice(index, 1);
        },
        attachReplaces: function (replaces) {
          this.selectedReplaces = null;
          if (this.replaces === undefined) {
            this.replaces = [];
          }
          this.replaces.push(replaces);
        },
        removeReplaces: function (index) {
          this.replaces.splice(index, 1);
        },
        attachNotification: function (notification) {
          this.selectedNotification = null;
          if (this.notifications === undefined) {
            this.notifications = [];
          }
          this.notifications.push(notification);
        },
        removeNotification: function (index) {
          this.notifications.splice(index, 1);
        },
        findDuplicates: function () {
          DomainService.findDomainByName(this.extensions.subAltNames[0]).then(function (domains) { //We should do a better job of searching for multiple domains
            this.duplicates = domains.total;
          });
        },
        useTemplate: function () {
          if (this.extensions === undefined) {
            this.extensions = {};
          }

          if (this.extensions.subAltNames === undefined) {
            this.extensions.subAltNames = {'names': []};
          }

          var saveSubAltNames = this.extensions.subAltNames;
          this.extensions = this.template.extensions;
          this.extensions.subAltNames = saveSubAltNames;
        },
        setEncipherOrDecipher: function (value) {
          if (this.extensions === undefined) {
            this.extensions = {};
          }
          if (this.extensions.keyUsage === undefined) {
            this.extensions.keyUsage = {};
          }
          var existingValue = this.extensions.keyUsage[value];
          if (existingValue) {
            // Clicked on the already-selected value
            this.extensions.keyUsage.useDecipherOnly = false;
            this.extensions.keyUsage.useEncipherOnly = false;
            // Uncheck both radio buttons
            this.encipherOrDecipher = false;
          } else {
            // Clicked a different value
            this.extensions.keyUsage.useKeyAgreement = true;
            if (value === 'useEncipherOnly') {
              this.extensions.keyUsage.useDecipherOnly = false;
              this.extensions.keyUsage.useEncipherOnly = true;
            } else {
              this.extensions.keyUsage.useEncipherOnly = false;
              this.extensions.keyUsage.useDecipherOnly = true;
            }
          }
        },
        setValidityEndDateRange: function (value) {
          // clear selected validity end date as we are about to calculate new range
          this.validityEnd = '';

          // Minimum end date will be same as selected start date
          this.authority.authorityCertificate.minValidityEnd = value;

          if(!this.authority.maxIssuanceDays) {
            this.authority.authorityCertificate.maxValidityEnd = this.authority.authorityCertificate.notAfter;
          } else {
            // Move max end date by maxIssuanceDays
            let endDate = new Date(value);
            endDate.setDate(endDate.getDate() + this.authority.maxIssuanceDays);
            this.authority.authorityCertificate.maxValidityEnd = endDate;
          }
        }
      });
    });
    return LemurRestangular.all('certificates');
  })
  .service('CertificateService', function ($location, CertificateApi, AuthorityService, AuthorityApi, LemurRestangular, DefaultService, DnsProviders) {
    var CertificateService = this;
    CertificateService.findCertificatesByName = function (filterValue) {
      return CertificateApi.getList({'filter[name]': filterValue})
        .then(function (certificates) {
          return certificates;
        });
    };

    CertificateService.create = function (certificate) {
      certificate.attachSubAltName();
      certificate.attachCustom();
      if (certificate.validityYears === '') { // if a user de-selects validity years we ignore it - might not be needed anymore
        delete certificate.validityYears;
      }
      return CertificateApi.post(certificate);
    };

    CertificateService.update = function (certificate) {
      return LemurRestangular.copy(certificate).put();
    };

    CertificateService.upload = function (certificate) {
      return CertificateApi.customPOST(certificate, 'upload');
    };

    CertificateService.getAuthority = function (certificate) {
      return certificate.customGET('authority').then(function (authority) {
        certificate.authority = authority;
      });
    };

    CertificateService.getCreator = function (certificate) {
      return certificate.customGET('creator').then(function (creator) {
        certificate.creator = creator;
      });
    };

    CertificateService.getDestinations = function (certificate) {
      return certificate.getList('destinations').then(function (destinations) {
        certificate.destinations = destinations;
      });
    };

    CertificateService.getNotifications = function (certificate) {
      return certificate.getList('notifications').then(function (notifications) {
        certificate.notifications = notifications;
      });
    };

    CertificateService.getDomains = function (certificate) {
      return certificate.getList('domains').then(function (domains) {
        certificate.domains = domains;
      });
    };

    CertificateService.getReplaces = function (certificate) {
      return certificate.getList('replaces').then(function (replaces) {
        certificate.replaces = replaces;
      });
    };

    CertificateService.getDefaults = function (certificate) {
      return DefaultService.get().then(function (defaults) {
        if (!certificate.country) {
          certificate.country = defaults.country;
        }

        if (!certificate.state) {
          certificate.state = defaults.state;
        }

        if (!certificate.location) {
          certificate.location = defaults.location;
        }

        if (!certificate.organization) {
          certificate.organization = defaults.organization;
        }

        if (!certificate.organizationalUnit) {
          certificate.organizationalUnit = defaults.organizationalUnit;
        }

        if (!certificate.authority) {
          if (!defaults.authority) {
            // set the default authority
            AuthorityApi.getList().then(function(authorities) {
              certificate.authority = authorities[0];
            });
          } else {
            certificate.authority = defaults.authority;
          }
        }

        certificate.authority.authorityCertificate.minValidityEnd = defaults.authority.authorityCertificate.notBefore;
        certificate.authority.authorityCertificate.maxValidityEnd = defaults.authority.authorityCertificate.notAfter;

        // pre-select validity type radio button to default days
        certificate.validityType = 'defaultDays';

        if (certificate.dnsProviderId) {
          certificate.dnsProvider = {id: certificate.dnsProviderId};
        }

        if(!certificate.keyType) {
          certificate.keyType = 'RSA2048'; // default algo to select during clone if backend did not return algo
        }

      });
    };

    CertificateService.getDnsProviders = function () {
      return DnsProviders.get();
    };

    CertificateService.loadPrivateKey = function (certificate) {
      return certificate.customGET('key');
    };

    CertificateService.updateSwitches = function (certificate) {
      return certificate.post();
    };

    CertificateService.export = function (certificate) {
      return certificate.customPOST(certificate.exportOptions, 'export');
    };

    CertificateService.revoke = function (certificate, crlReason) {
      return certificate.customPUT({'crlReason':crlReason}, 'revoke');
    };

    return CertificateService;
  });

