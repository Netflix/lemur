'use strict';

angular.module('lemur')
  .config(function config($routeProvider) {
    $routeProvider.when('/login', {
      templateUrl: '/angular/authentication/login/login.tpl.html',
      controller: 'LoginController'
    });
  })
  .controller('LoginController', function ($rootScope, $scope, AuthenticationService, UserService) {
    $scope.login = AuthenticationService.login;
    $scope.authenticate = AuthenticationService.authenticate;
    $scope.logout = AuthenticationService.logout;

    UserService.getCurrentUser().then(function (user) {
      $scope.currentUser = user;
    });

    $rootScope.$on('user:login', function () {
      UserService.getCurrentUser().then(function (user) {
        $scope.currentUser = user;
      });
    });

    $rootScope.$on('user:logout', function () {
      $scope.currentUser = null;
    });
  });
