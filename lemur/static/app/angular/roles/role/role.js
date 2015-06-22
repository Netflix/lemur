'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/roles/create', {
      templateUrl: '/angular/roles/role/role.tpl.html',
      controller: 'RoleCreateController'
    });
    $routeProvider.when('/roles/:id/edit', {
      templateUrl: '/angular/roles/role/role.tpl.html',
      controller: 'RoleEditController'
    });
  })
  .controller('RoleEditController', function ($scope, $routeParams, RoleApi, RoleService, UserService) {
    RoleApi.get($routeParams.id).then(function (role) {
      $scope.role = role;
      RoleService.getUsers(role);
    });

    $scope.save = RoleService.update;
    $scope.userService = UserService;
    $scope.roleService = RoleService;
  })

  .controller('RoleCreateController', function ($scope, RoleApi, RoleService, UserService, LemurRestangular ) {
    $scope.role = LemurRestangular.restangularizeElement(null, {}, 'roles');
    $scope.userService = UserService;
    $scope.save = RoleService.create;
  });
