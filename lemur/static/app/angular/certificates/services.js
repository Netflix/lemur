'use strict';

angular.module('lemur')
  .service('CertificateApi', function (LemurRestangular, DomainService) {
    LemurRestangular.extendModel('certificates', function (obj) {
      return angular.extend(obj, {
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
           this.subAltType = 'CNAME';
         }

         if (angular.isString(this.subAltValue) && angular.isString(this.subAltType)) {
           this.extensions.subAltNames.names.push({'nameType': this.subAltType, 'value': this.subAltValue});
           this.findDuplicates();
         }

         this.subAltType = null;
         this.subAltValue = null;
       },
        removeSubAltName: function (index) {
          this.extensions.subAltNames.names.splice(index, 1);
          this.findDuplicates();
        },
        attachCustom: function () {
          if (this.extensions === undefined || this.extensions.custom === undefined) {
            this.extensions = {'custom': []};
          }

          if (angular.isString(this.customOid) && angular.isString(this.customEncoding) && angular.isString(this.customValue)) {
            this.extensions.custom.push(
              {
                'oid': this.customOid,
                'isCritical': this.customIsCritical,
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
        attachELB: function (elb) {
          this.selectedELB = null;
          if (this.elbs === undefined) {
            this.elbs = [];
          }
          this.elbs.push(elb);
        },
        removeELB: function (index) {
          this.elbs.splice(index, 1);
        },
        findDuplicates: function () {
          DomainService.findDomainByName(this.extensions.subAltNames[0]).then(function (domains) { //We should do a better job of searchin multiple domains
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
  .service('CertificateService', function ($location, CertificateApi, LemurRestangular, toaster) {
    var CertificateService = this;
    CertificateService.findCertificatesByName = function (filterValue) {
      return CertificateApi.getList({'filter[name]': filterValue})
        .then(function (certificates) {
          return certificates;
        });
    };

    CertificateService.create = function (certificate) {
      certificate.attachSubAltName();
      return CertificateApi.post(certificate).then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully created!'
          });
          $location.path('/certificates');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Was not created! ' + response.data.message
          });
        }
      );
    };

    CertificateService.update = function (certificate) {
      return LemurRestangular.copy(certificate).put().then(function () {
        toaster.pop({
          type: 'success',
          title: certificate.name,
          body: 'Successfully updated!'
        });
        $location.path('certificates');
      });
    };

    CertificateService.upload = function (certificate) {
      return CertificateApi.customPOST(certificate, 'upload').then(
        function () {
          toaster.pop({
            type: 'success',
            title: certificate.name,
            body: 'Successfully uploaded!'
          });
          $location.path('/certificates');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'Failed to upload ' + response.data.message
          });
      });
    };

    CertificateService.loadPrivateKey = function (certificate) {
      return certificate.customGET('key').then(
        function (response) {
          if (response.key === null) {
            toaster.pop({
              type: 'warning',
              title: certificate.name,
              body: 'No private key found!'
            });
          } else {
            certificate.privateKey = response.key;
          }
        },
        function () {
          toaster.pop({
            type: 'error',
            title: certificate.name,
            body: 'You do not have permission to view this key!'
          });
        });
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

    CertificateService.getListeners = function (certificate) {
      return certificate.getList('listeners').then(function (listeners) {
        certificate.listeners = listeners;
      });
    };

    CertificateService.getELBs = function (certificate) {
      return certificate.getList('listeners').then(function (elbs) {
        certificate.elbs = elbs;
      });
    };

    CertificateService.getDomains = function (certificate) {
      return certificate.getList('domains').then(function (domains) {
        certificate.domains = domains;
      });
    };

    CertificateService.updateActive = function (certificate) {
      return certificate.put().then(
          function () {
            toaster.pop({
              type: 'success',
              title: certificate.name,
              body: 'Successfully updated!'
            });
          },
          function (response) {
            toaster.pop({
              type: 'error',
              title: certificate.name,
              body: 'Was not updated! ' + response.data.message
            });
          });
    };

    return CertificateService;
  });
