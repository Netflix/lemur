/**
 * Created by kglisson on 1/19/15.
 */
'use strict';
angular.module('lemur')
  .service('UserApi', function (LemurRestangular, ApiKeyService) {
    LemurRestangular.extendModel('users', function (obj) {
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
        removeApiKey: function (index) {
          var removedApiKeys = this.apiKeys.splice(index, 1);
          var removedApiKey = removedApiKeys[0];
          return ApiKeyService.delete(removedApiKey);
        }
      });
    });
    return LemurRestangular.all('users');
  })
  .service('UserService', function ($location, UserApi, AuthenticationApi) {
    var UserService = this;
    UserService.getCurrentUser = function () {
      return AuthenticationApi.customGET('me').then(function (user) {
        return user;
      });
    };

    UserService.findUserByName = function (filterValue) {
      return UserApi.getList({'filter[username]': filterValue})
        .then(function (users) {
          return users;
        });
    };

    UserService.getRoles = function (user) {
      user.getList('roles').then(function (roles) {
        user.roles = roles;
      });
    };

    UserService.getApiKeys = function (user) {
      user.getList('keys').then(function (apiKeys) {
        user.apiKeys = apiKeys;
      });
    };

    UserService.loadMoreRoles = function (user, page) {
      user.getList('roles', {page: page}).then(function (roles) {
        _.each(roles, function (role) {
          user.roles.push(role);
        });
      });
    };

    UserService.loadMoreApiKeys = function (user, page) {
      user.getList('keys', {page: page}).then(function (apiKeys) {
        _.each(apiKeys, function (apiKey) {
          user.apiKeys.push(apiKey);
        });
      });
    };

    UserService.create = function (user) {
      return UserApi.post(user);
    };

    UserService.update = function (user) {
      return user.put();
    };
  });
