'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/accounts/create', {
      templateUrl: '/angular/accounts/account/account.tpl.html',
      controller: 'AccountsCreateController'
    });
    $routeProvider.when('/accounts/:id/edit', {
      templateUrl: '/angular/accounts/account/account.tpl.html',
      controller: 'AccountsEditController'
    });
  })

  .controller('AccountsCreateController', function ($scope, AccountService, LemurRestangular){
    $scope.account = LemurRestangular.restangularizeElement(null, {}, 'accounts');
    $scope.save = AccountService.create;
  })

  .controller('AccountsEditController', function ($scope, $routeParams, AccountService, AccountApi) {
    AccountApi.get($routeParams.id).then(function (account) {
      $scope.account = account;
    });

    $scope.save = AccountService.update;
  });
