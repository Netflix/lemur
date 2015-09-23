'use strict';
angular.module('lemur')
  .service('AuthenticationApi', function (LemurRestangular) {
    return LemurRestangular.all('auth');
  })
  .service('AuthenticationService', function ($location, $rootScope, AuthenticationApi, UserService, toaster, $auth) {
    var AuthenticationService = this;

    AuthenticationService.login = function (username, password) {
      AuthenticationApi.customPOST({'username': username, 'password': password}, 'login')
        .then(
            function (user) {
              $auth.setToken(user.token, true);
              $rootScope.$emit('user:login');
              $location.url('/certificates');
            },
            function (response) {
              toaster.pop({
                type: 'error',
                title: 'Whoa there',
                body: response.data.message,
                showCloseButton: true
              });
            }
      );
    };

    AuthenticationService.authenticate = function (provider) {
      $auth.authenticate(provider)
        .then(
          function () {
            UserService.getCurrentUser();
            $rootScope.$emit('user:login');
            $location.url('/certificates');
          },
          function (response) {
            toaster.pop({
              type: 'error',
              title: 'Something went wrong',
              body: response.data.message
            });
          }
      );
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
          $location.path('/');
        });
    };

  });
