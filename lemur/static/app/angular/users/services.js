/**
 * Created by kglisson on 1/19/15.
 */
'use strict';
angular.module('lemur')
  .service('UserApi', function (LemurRestangular) {
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

    UserService.loadMoreRoles = function (user, page) {
      user.getList('roles', {page: page}).then(function (roles) {
        _.each(roles, function (role) {
          user.roles.push(role);
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
