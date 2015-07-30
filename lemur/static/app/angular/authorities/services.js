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
          if (this.extensions === undefined || this.extensions.subAltNames === undefined) {
            this.extensions = {'subAltNames': {'names': []}};
          }

          if (angular.isString(this.subAltType) && angular.isString(this.subAltValue)) {
            this.extensions.subAltNames.names.push({'nameType': this.subAltType, 'value': this.subAltValue});
          }

          this.subAltType = null;
          this.subAltValue = null;
        },
        removeSubAltName: function (index) {
          this.extensions.subAltNames.names.splice(index, 1);
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
        }
      });
    });
    return LemurRestangular.all('authorities');
  })
  .service('AuthorityService', function ($location, AuthorityApi, toaster) {
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
          var activeAuthorities = [];
          _.each(authorities, function (authority) {
              if (authority.active) {
                activeAuthorities.push(authority);
              }
          });
          return activeAuthorities;
        });
    };

    AuthorityService.create = function (authority) {
      authority.attachSubAltName();
      return AuthorityApi.post(authority).then(
        function () {
          toaster.pop({
            type: 'success',
            title: authority.name,
            body: 'Successfully created!'
          });
          $location.path('/authorities');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: authority.name,
            body: 'Was not created! ' + response.data.message
          });
        });
    };

    AuthorityService.update = function (authority) {
      return authority.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: authority.name,
            body: 'Successfully updated!'
          });
          $location.path('/authorities');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: authority.name,
            body: 'Update Failed! ' + response.data.message
          });
      });
    };

    AuthorityService.getRoles = function (authority) {
      return authority.getList('roles').then(function (roles) {
        authority.roles = roles;
      });
    };

    AuthorityService.updateActive = function (authority) {
      return authority.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: authority.name,
            body: 'Successfully updated!'
          });
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: authority.name,
            body: 'Update Failed! ' + response.data.message
          });
        });
    };
  });
