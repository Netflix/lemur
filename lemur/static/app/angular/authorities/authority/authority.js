'use strict';

angular.module('lemur')

  .controller('AuthorityEditController', function ($scope, $uibModalInstance, AuthorityApi, AuthorityService, RoleService, toaster, editId){
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
          $uibModalInstance.close();
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
      $uibModalInstance.dismiss('cancel');
    };
  })

  .controller('AuthorityCreateController', function ($scope, $uibModalInstance, AuthorityService, AuthorityApi, LemurRestangular, RoleService, PluginService, WizardHandler, toaster)  {
    $scope.authority = LemurRestangular.restangularizeElement(null, {}, 'authorities');

    $scope.authorities = [];
    AuthorityApi.getList().then(function (authorities) {
      angular.extend($scope.authorities, authorities);
    });

    $scope.authorityConfig = {
      valueField: 'id',
      labelField: 'name',
      placeholder: 'Select Authority',
      maxItems: 1,
      onChange: function (value) {
        angular.forEach($scope.authorities, function (authority) {
          if (authority.id === parseInt(value)) {
            $scope.authority.authority = authority;
          }
        });
      },
      render: {
        option: function(item) {
            return '<div><dl>' +
                '<dt>' +
                    '<span>' + item.name + ' <small>' + item.owner + '</small></span>' +
                '</dt>' +
                '<dd>' +
                  '<span>' + item.description + '</span>' +
                '</dd>' +
            '</dl></div>';
        }
      },
      load: function (value) {
        AuthorityService.findAuthorityByName(value).then(function (authorities) {
          $scope.authorities = authorities;
        })
      }
    };

    // set the defaults
    AuthorityService.getDefaults($scope.authority);

    AuthorityApi.getList().then(function (authorities) {
      $scope.authorities = authorities;
    });

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
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
					$uibModalInstance.close();
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

    $scope.dateOptions = {
      formatYear: 'yy',
      maxDate: new Date(2020, 5, 22),
      minDate: new Date(),
      startingDay: 1
    };


    $scope.open1 = function() {
      $scope.popup1.opened = true;
    };

    $scope.open2 = function() {
      $scope.popup2.opened = true;
    };

    $scope.setDate = function(year, month, day) {
      $scope.dt = new Date(year, month, day);
    };

    $scope.formats = ['dd-MMMM-yyyy', 'yyyy/MM/dd', 'dd.MM.yyyy', 'shortDate'];
    $scope.format = $scope.formats[0];
    $scope.altInputFormats = ['M!/d!/yyyy'];

    $scope.popup1 = {
      opened: false
    };

    $scope.popup2 = {
      opened: false
    };

  });
