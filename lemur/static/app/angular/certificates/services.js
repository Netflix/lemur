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
        attachSubAltName: function () {
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
            //this.findDuplicates();
          }

          this.subAltType = null;
          this.subAltValue = null;
        },
        removeSubAltName: function (index) {
          this.extensions.subAltNames.names.splice(index, 1);
          //this.findDuplicates();
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
          this.extensions = this.template.extensions;
        }
      });
    });
    return LemurRestangular.all('certificates');
  })
  .service('CertificateService', function ($location, CertificateApi, AuthorityService, AuthorityApi, LemurRestangular, DefaultService) {
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
      if (certificate.validityYears === '') { // if a user de-selects validity years we ignore it
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
      });
    };

    CertificateService.loadPrivateKey = function (certificate) {
      return certificate.customGET('key');
    };

    CertificateService.updateNotify = function (certificate) {
      return certificate.put();
    };

    CertificateService.export = function (certificate) {
      return certificate.customPOST(certificate.exportOptions, 'export');
    };

    return CertificateService;
  });
