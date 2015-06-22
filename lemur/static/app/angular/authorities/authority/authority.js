'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/authorities/create', {
      templateUrl: '/angular/authorities/authority/authorityWizard.tpl.html',
      controller: 'AuthorityCreateController'
    });
    $routeProvider.when('/authorities/:id/edit', {
      templateUrl: '/angular/authorities/authority/authorityEdit.tpl.html',
      controller: 'AuthorityEditController'
    });
  })

  .controller('AuthorityEditController', function ($scope, $routeParams, AuthorityApi, AuthorityService, RoleService){
    AuthorityApi.get($routeParams.id).then(function (authority) {
      AuthorityService.getRoles(authority);
      $scope.authority = authority;
    });

    $scope.authorityService = AuthorityService;
    $scope.save = AuthorityService.update;
    $scope.roleService = RoleService;
  })

  .controller('AuthorityCreateController', function ($scope, $modal, AuthorityService, LemurRestangular, RoleService)  {
    $scope.authority = LemurRestangular.restangularizeElement(null, {}, 'authorities');

    $scope.save = function (authority) {
      var loadingModal = $modal.open({backdrop: 'static', template: '<wave-spinner></wave-spinner>', windowTemplateUrl: 'angular/loadingModal.html', size: 'large'});
      return AuthorityService.create(authority).then(function (response) {
        loadingModal.close();
      });
    };


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
