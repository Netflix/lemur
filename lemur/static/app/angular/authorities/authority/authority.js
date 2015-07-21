'use strict';

angular.module('lemur')

  .controller('AuthorityEditController', function ($scope, $routeParams, AuthorityApi, AuthorityService, RoleService){
    AuthorityApi.get($routeParams.id).then(function (authority) {
      AuthorityService.getRoles(authority);
      $scope.authority = authority;
    });

    $scope.authorityService = AuthorityService;
    $scope.save = AuthorityService.update;
    $scope.roleService = RoleService;
  })

  .controller('AuthorityCreateController', function ($scope, $modalInstance, AuthorityService, LemurRestangular, RoleService, PluginService, WizardHandler)  {
    $scope.authority = LemurRestangular.restangularizeElement(null, {}, 'authorities');

    $scope.loading = false;
    $scope.create = function (authority) {
      WizardHandler.wizard().context.loading = true;
      AuthorityService.create(authority).then(function () {
        WizardHandler.wizard().context.loading = false;
        $modalInstance.close();
      });
    };

    PluginService.get('issuer').then(function (plugins) {
        $scope.plugins = plugins;
    });

    $scope.roleService = RoleService;

    $scope.authorityService = AuthorityService;

    $scope.open = function($event) {
      $event.preventDefault();
      $event.stopPropagation();

      $scope.opened1 = true;
    };

    $scope.open2 = function($event) {
      $event.preventDefault();
      $event.stopPropagation();

      $scope.opened2 = true;
    };
  });
