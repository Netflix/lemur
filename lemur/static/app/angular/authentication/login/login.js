'use strict';

angular.module('lemur')
  .config(function config($stateProvider) {
    $stateProvider.state('login', {
      url: '/login',
      templateUrl: '/angular/authentication/login/login.tpl.html',
      controller: 'LoginController',
      params: {
        'toState': 'certificates',
        'toParams': {}
      }
    });
  })
  .controller('LoginController', function ($rootScope, $scope, $state, $auth, AuthenticationService, UserService, providers, toaster) {
    $scope.login = function (username, password) {
      return AuthenticationService.login(username, password).then(
        function (user) {
          $auth.setToken(user.token, true);
          $rootScope.$emit('user:login');
          $state.go($state.params.toState, $state.params.toParams);
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: 'Whoa there',
            body: response.data.message,
            showCloseButton: true
          });
        });
    };

    $scope.authenticate = function (provider) {
      return AuthenticationService.authenticate(provider).then(
        function (user) {
          $auth.setToken(user.token, true);
          $rootScope.$emit('user:login');
          $state.go($state.params.toState, $state.params.toParams);
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: 'Whoa there',
            body: response.data.message,
            showCloseButton: true
          });
        });
    };

    $scope.logout = AuthenticationService.logout;

    $scope.providers = providers;

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