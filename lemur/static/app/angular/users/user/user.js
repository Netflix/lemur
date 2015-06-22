'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/users/create', {
      templateUrl: '/angular/users/user/user.tpl.html',
      controller: 'UsersCreateController'
    });
    $routeProvider.when('/users/:id/edit', {
      templateUrl: '/angular/users/user/user.tpl.html',
      controller: 'UsersEditController'
    });
  })

  .controller('UsersEditController', function ($scope, $routeParams, UserApi, UserService, RoleService) {
    UserApi.get($routeParams.id).then(function (user) {
      UserService.getRoles(user);
      $scope.user = user;
    });

    $scope.save = UserService.update;
    $scope.roleService = RoleService;

    $scope.rolePage = 1;

    $scope.loadMoreRoles = function () {
      $scope.rolePage += 1;
      UserService.loadMoreRoles($scope.user, $scope.rolePage);
    };
  })

  .controller('UsersCreateController', function ($scope, UserService, LemurRestangular, RoleService) {
    $scope.user = LemurRestangular.restangularizeElement(null, {}, 'users');
    $scope.save = UserService.create;
    $scope.roleService = RoleService;

  });
