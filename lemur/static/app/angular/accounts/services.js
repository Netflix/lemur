'use strict';
angular.module('lemur')
  .service('AccountApi', function (LemurRestangular) {
    return LemurRestangular.all('accounts');
  })
  .service('AccountService', function ($location, AccountApi, toaster) {
    var AccountService = this;
    AccountService.findAccountsByName = function (filterValue) {
      return AccountApi.getList({'filter[label]': filterValue})
        .then(function (accounts) {
          return accounts;
        });
    };

    AccountService.create = function (account) {
      AccountApi.post(account).then(
        function () {
          toaster.pop({
            type: 'success',
            title: account.label,
            body: 'Successfully created!'
          });
          $location.path('accounts');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: account.label,
            body: 'Was not created! ' + response.data.message
          });
        });
    };

    AccountService.update = function (account) {
      account.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: account.label,
            body: 'Successfully updated!'
          });
          $location.path('accounts');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: account.label,
            body: 'Was not updated! ' + response.data.message
          });
        });
    };
    return AccountService;
  });
