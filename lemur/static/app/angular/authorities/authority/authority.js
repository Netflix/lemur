'use strict';

angular.module('lemur')

  .controller('AuthorityEditController', function ($scope, $modalInstance, AuthorityApi, AuthorityService, RoleService, toaster, editId){
    AuthorityApi.get(editId).then(function (authority) {
      $scope.authority = authority;
    });

    $scope.roleService = RoleService;

    $scope.save = function (authority) {
      AuthorityService.update(authority).then(
        function () {
          toaster.pop({
            type: 'success',
            title: authority.name,
            body: 'Successfully updated!'
          });
          $modalInstance.close();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: authority.name,
            body: 'Update Failed! ' + response.data.message,
            timeout: 100000
          });
        });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };
  })

  .controller('AuthorityCreateController', function ($scope, $modalInstance, AuthorityService, LemurRestangular, RoleService, PluginService, WizardHandler, toaster)  {
    $scope.authority = LemurRestangular.restangularizeElement(null, {}, 'authorities');

    // set the defaults
    AuthorityService.getDefaults($scope.authority);

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.create = function (authority) {
      WizardHandler.wizard().context.loading = true;
      AuthorityService.create(authority).then(
				function () {
          toaster.pop({
            type: 'success',
            title: authority.name,
            body: 'Was created!'
          });
					$modalInstance.close();
				},
				function (response) {
					toaster.pop({
						type: 'error',
						title: authority.name,
						body: 'Was not created! ' + response.data.message,
            timeout: 100000
					});
          WizardHandler.wizard().context.loading = false;
      });
    };

    PluginService.getByType('issuer').then(function (plugins) {
        $scope.plugins = plugins;
        $scope.authority.plugin = plugins[0];
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
