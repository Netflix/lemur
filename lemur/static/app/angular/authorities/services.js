'use strict';
angular.module('lemur')
  .service('AuthorityApi', function (LemurRestangular) {
    LemurRestangular.extendModel('authorities', function (obj) {
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
        }
      });
    });
    return LemurRestangular.all('authorities');
  })
  .service('AuthorityService', function ($location, AuthorityApi, DefaultService) {
    var AuthorityService = this;
    AuthorityService.findAuthorityByName = function (filterValue) {
      return AuthorityApi.getList({'filter[name]': filterValue})
        .then(function (authorites) {
          return authorites;
        });
    };

    AuthorityService.findActiveAuthorityByName = function (filterValue) {
      return AuthorityApi.getList({'filter[name]': filterValue})
        .then(function (authorities) {
          return authorities.filter(function(authority) { return authority.active; });
        });
    };

    AuthorityService.create = function (authority) {
      authority.attachSubAltName();
      authority.attachCustom();

      if (authority.extensions.basicConstraints === undefined) {
        authority.extensions.basicConstraints = { 'path_length': null};
      }
      authority.extensions.basicConstraints.ca = true;
      if (authority.extensions.basicConstraints.path_length === 'None') {
        authority.extensions.basicConstraints.path_length = null;
      }

      if (authority.validityYears === '') { // if a user de-selects validity years we ignore it
        delete authority.validityYears;
      }
      return AuthorityApi.post(authority);
    };

    AuthorityService.update = function (authority) {
      return authority.put();
    };

    AuthorityService.getDefaults = function (authority) {
      return DefaultService.get().then(function (defaults) {
        authority.country = defaults.country;
        authority.state = defaults.state;
        authority.location = defaults.location;
        authority.organization = defaults.organization;
        authority.organizationalUnit = defaults.organizationalUnit;
        authority.defaultIssuerPlugin = defaults.issuerPlugin;
      });
    };

    AuthorityService.getRoles = function (authority) {
      return authority.getList('roles').then(function (roles) {
        authority.roles = roles;
      });
    };

    AuthorityService.updateActive = function (authority) {
      return authority.put();
    };

  });
