'use strict';

angular.module('lemur')
  .config(function config($routeProvider) {
    $routeProvider.when('/unlock', {
      templateUrl: '/angular/authentication/unlock/unlock.tpl.html',
      controller: 'UnlockCtrl'
    });
  })
  .controller('UnlockCtrl', function ($scope, $location, lemurRestangular, messageService) {
    $scope.unlock = function () {
      lemurRestangular.one('unlock').customPOST({'password': $scope.password})
        .then(function (data) {
          messageService.addMessage(data);
          $location.path('/dashboard');
        });
    };
  });
