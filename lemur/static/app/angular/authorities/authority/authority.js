'use strict';

angular.module('lemur')

  .controller('AuthorityEditController', function ($scope, $modalInstance, AuthorityApi, AuthorityService, RoleService, editId){
    AuthorityApi.get(editId).then(function (authority) {
      AuthorityService.getRoles(authority);
      $scope.authority = authority;
    });

    $scope.authorityService = AuthorityService;
    $scope.roleService = RoleService;

    $scope.save = function (authority) {
      AuthorityService.update(authority).then(
        function () {
          $modalInstance.close();
        },
        function () {

        }
      );
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };
  })

  .controller('AuthorityCreateController', function ($scope, $modalInstance, AuthorityService, LemurRestangular, RoleService, PluginService, WizardHandler)  {
    $scope.authority = LemurRestangular.restangularizeElement(null, {}, 'authorities');

    // set the defaults
    AuthorityService.getDefaults($scope.authority);

    $scope.loading = false;
    $scope.create = function (authority) {
      WizardHandler.wizard().context.loading = true;
      AuthorityService.create(authority).then(function () {
        WizardHandler.wizard().context.loading = false;
        $modalInstance.close();
      });
    };

    PluginService.getByType('issuer').then(function (plugins) {
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
