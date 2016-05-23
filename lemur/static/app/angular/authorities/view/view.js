'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider
      .state('authorities', {
        url: '/authorities',
        templateUrl: '/angular/authorities/view/view.tpl.html',
        controller: 'AuthoritiesViewController'
      })
      .state('authority', {
        url: '/authorities/:name',
        templateUrl: '/angular/authorities/view/view.tpl.html',
        controller: 'AuthoritiesViewController'
      });
  })

  .controller('AuthoritiesViewController', function ($scope, $q, $uibModal, $stateParams, AuthorityApi, AuthorityService, MomentService, ngTableParams, toaster) {
    $scope.filter = $stateParams;
    $scope.authoritiesTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        AuthorityApi.getList(params.url()).then(function (data) {
          params.total(data.total);
          $defer.resolve(data);
        });
      }
    });

    $scope.momentService = MomentService;

    $scope.updateActive = function (authority) {
      AuthorityService.updateActive(authority).then(
				function () {
					toaster.pop({
						type: 'success',
						title: authority.name,
						body: 'Successfully updated!'
					});
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

    $scope.getAuthorityStatus = function () {
      var def = $q.defer();
      def.resolve([{'title': 'Active', 'id': true}, {'title': 'Inactive', 'id': false}]);
      return def;
    };

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

    $scope.edit = function (authorityId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/authorities/authority/edit.tpl.html',
        controller: 'AuthorityEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return authorityId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.authoritiesTable.reload();
      });

    };

    $scope.editRole = function (roleId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/roles/role/role.tpl.html',
        controller: 'RolesEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return roleId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.authoritiesTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'AuthorityCreateController',
        templateUrl: '/angular/authorities/authority/authorityWizard.tpl.html',
        size: 'lg',
        backdrop: 'static',
      });

      uibModalInstance.result.then(function () {
        $scope.authoritiesTable.reload();
      });

    };
  });
