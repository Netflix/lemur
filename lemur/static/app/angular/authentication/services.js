'use strict';
angular.module('lemur')
  .service('AuthenticationApi', function (LemurRestangular) {
    return LemurRestangular.all('auth');
  })
  .service('AuthenticationService', function ($location, $rootScope, AuthenticationApi, UserService, toaster, $auth) {
    var AuthenticationService = this;

    AuthenticationService.login = function (username, password) {
      return AuthenticationApi.customPOST({'username': username, 'password': password}, 'login');
    };

    AuthenticationService.authenticate = function (provider) {
      return $auth.authenticate(provider);
    };

    AuthenticationService.logout = function () {
      if (!$auth.isAuthenticated()) {
        return;
      }
      $auth.logout()
        .then(function() {
          $rootScope.$emit('user:logout');
          toaster.pop({
            type: 'success',
            title: 'Good job!',
            body: 'You have been successfully logged out.'
          });
          $location.path('/login');
        });
    };
  });