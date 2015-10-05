'use strict';

angular.module('lemur')
  .config(function config($stateProvider) {
    $stateProvider.state('logout', {
      controller: 'LogoutCtrl',
      url: '/logout'
    });
  })
  .controller('LogoutCtrl', function ($scope, $location, lemurRestangular, userService) {
    userService.logout();
    $location.path('/');
  });
