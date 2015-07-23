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
  .service('RoleService', function ($location, RoleApi, toaster) {
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
      role.customGET('users').then(function (users) {
        role.users = users;
      });
    };

    RoleService.create = function (role) {
      return RoleApi.post(role).then(
        function () {
          toaster.pop({
            type: 'success',
            title: role.name,
            body: 'Has been successfully created!'
          });
          $location.path('roles');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: role.name,
            body: 'Has not been created! ' + response.data.message
          });
        });
    };

    RoleService.update = function (role) {
      return role.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: role.name,
            body: 'Successfully updated!'
          });
          $location.path('roles');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: role.name,
            body: 'Was not updated!' + response.data.message
          });
        });
    };

    RoleService.remove = function (role) {
      return role.remove().then(
        function () {
          toaster.pop({
            type: 'success',
            title: role.name,
            body: 'Successfully deleted!'
          });
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: role.name,
            body: 'Was not deleted!' + response.data.message
          });
        }
      );
    };

    RoleService.loadPassword = function (role) {
      return role.customGET('credentials').then(
        function (response) {
          if ( response.password === null) {
            toaster.pop({
              type: 'info',
              title: role.name,
              body: 'Has no password associated'
            });
          } else {
            role.password = response.password;
            role.username = response.username;
          }
        },
        function () {
          toaster.pop({
            type: 'error',
            title: role.name,
            body: 'You do not have permission to view this password!'
          });
        });
    };
  });
