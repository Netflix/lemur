'use strict';

angular.module('lemur')
  .config(function config($routeProvider) {
    $routeProvider.when('/logout', {
      controller: 'LogoutCtrl'
    });
  })
  .controller('LogoutCtrl', function ($scope, $location, lemurRestangular, userService) {
    userService.logout();
    $location.path('/');
  });
