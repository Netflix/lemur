'use strict';

angular.module('lemur')
  .config(function config($stateProvider) {
    $stateProvider.state('dashboard', {
      url: '/dashboard',
      templateUrl: '/angular/dashboard/dashboard.tpl.html',
      controller: 'DashboardController'
    });
  })
  .controller('DashboardController', function ($scope, $rootScope, $filter, $location, LemurRestangular) {

    $scope.colors = [
      {
        fillColor: 'rgba(41, 171, 224, 0.2)',
        strokeColor: 'rgba(41, 171, 224, 1)',
        pointColor: 'rgba(41, 171, 224, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(41, 171, 224, 0.8)'
      }, {
        fillColor: 'rgba(147, 197, 75, 0.2)',
        strokeColor: 'rgba(147, 197, 75, 1)',
        pointColor: 'rgba(147, 197, 75, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(147, 197, 75, 0.8)'
      }, {
        fillColor: 'rgba(217, 83, 79, 0.2)',
        strokeColor: 'rgba(217, 83, 79, 1)',
        pointColor: 'rgba(217, 83, 79, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(217, 83, 79, 0.8)'
      }, {
        fillColor: 'rgba(244, 124, 60, 0.2)',
        strokeColor: 'rgba(244, 124, 60, 1)',
        pointColor: 'rgba(244, 124, 60, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(244, 124, 60, 0.8)'
      }, {
        fillColor: 'rgba(243, 156, 18, 0.2)',
        strokeColor: 'rgba(243, 156, 18, 1)',
        pointColor: 'rgba(243, 156, 18, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(243, 156, 18, 0.8)'
      }, {
        fillColor: 'rgba(231, 76, 60, 0.2)',
        strokeColor: 'rgba(231, 76, 60, 1)',
        pointColor: 'rgba(231, 76, 60, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(231, 76, 60, 0.8)'
      }, {
        fillColor: 'rgba(255, 102, 102, 0.2)',
        strokeColor: 'rgba(255, 102, 102, 1)',
        pointColor: 'rgba(255, 102, 102, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(255, 102, 102, 0.8)'
      }, {
        fillColor: 'rgba(255, 230, 230, 0.2)',
        strokeColor: 'rgba(255, 230, 230, 1)',
        pointColor: 'rgba(255, 230, 230, 0.2)',
        pointStrongColor: '#fff',
        pointHighlightFill: '#fff',
        pointHighlightStrokeColor: 'rgba(255, 230, 230, 0.8)'
      }];

    LemurRestangular.all('certificates').customGET('stats', {metric: 'issuer'})
      .then(function (data) {
        $scope.issuers = data.items;
      });

    LemurRestangular.all('certificates').customGET('stats', {metric: 'bits'})
      .then(function (data) {
        $scope.bits = data.items;
      });

		LemurRestangular.all('certificates').customGET('stats', {metric: 'signing_algorithm'})
			.then(function (data) {
				$scope.algos = data.items;
			});

    LemurRestangular.all('certificates').customGET('stats', {metric: 'not_after'})
      .then(function (data) {
        $scope.expiring = {labels: data.items.labels, values: [data.items.values]};
      });

    LemurRestangular.all('destinations').customGET('stats', {metric: 'certificate'})
      .then(function (data) {
        $scope.destinations = data.items;
      });
  });
