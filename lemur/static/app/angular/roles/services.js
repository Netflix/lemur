'use strict';

angular.module('lemur')
  .service('RoleApi', function (LemurRestangular) {
    LemurRestangular.extendModel('roles', function (obj) {
      return angular.extend(obj, {
        addUser: function (user) {
          this.selectedUser = null;
          if (this.users === undefined) {
            this.users = [];
          }
          this.users.push(user);
        },
        removeUser: function (index) {
          this.users.splice(index, 1);
        }
      });
    });
    return LemurRestangular.all('roles');
  })
  .service('RoleService', function ($location, RoleApi) {
    var RoleService = this;
    RoleService.findRoleByName = function (filterValue) {
      return RoleApi.getList({'filter[name]': filterValue})
        .then(function (roles) {
          return roles;
        });
    };

    RoleService.getRoleDropDown = function () {
      return RoleApi.getList().then(function (roles) {
        return roles;
      });
    };

    RoleService.getUsers = function (role) {
      return role.getList('users').then(function (users) {
        role.users = users;
      });
    };

    RoleService.loadMoreUsers = function (role, page) {
      role.getList('users', {page: page}).then(function (users) {
        _.each(users, function (user) {
          role.users.push(user);
        });
      });
    };

    RoleService.create = function (role) {
      return RoleApi.post(role);
    };

    RoleService.update = function (role) {
      return role.put();
    };

    RoleService.remove = function (role) {
      return role.remove();
    };

    RoleService.loadPassword = function (role) {
      return role.customGET('credentials');
    };
  });
