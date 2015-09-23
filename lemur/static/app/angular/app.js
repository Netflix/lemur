'use strict';

var lemur = angular
  .module('lemur', [
    'ngRoute',
    'ngTable',
    'ngAnimate',
    'chart.js',
    'restangular',
    'angular-loading-bar',
    'ui.bootstrap',
    'angular-spinkit',
    'toaster',
    'uiSwitch',
    'mgo-angular-wizard',
    'satellizer'
  ])
  .config(function ($routeProvider, $authProvider) {
    $routeProvider
      .when('/', {
        templateUrl: 'angular/welcome/welcome.html'
      })
      .otherwise({
        redirectTo: '/'
      });

    $authProvider.oauth2({
      name: 'example',
      url: 'http://localhost:5000/api/1/auth/ping',
      redirectUri: 'http://localhost:3000/',
      clientId: 'client-id',
      responseType: 'code',
      scope: ['openid', 'email', 'profile', 'address'],
      scopeDelimiter: ' ',
      authorizationEndpoint: 'https://example.com/as/authorization.oauth2',
      requiredUrlParams: ['scope']
    });
  });

lemur.service('MomentService', function () {
  this.diffMoment = function (start, end) {
    if (end !== 'None') {
      return moment(end, 'YYYY-MM-DD HH:mm Z').diff(moment(start, 'YYYY-MM-DD HH:mm Z'), 'minutes') + ' minutes';
    }
    return 'Unknown';
  };
  this.createMoment = function (date) {
    if (date !== 'None') {
      return moment(date, 'YYYY-MM-DD HH:mm Z').fromNow();
    }
    return 'Unknown';
  };
});

lemur.controller('datePickerController', function ($scope, $timeout){
  $scope.open = function() {
    $timeout(function() {
      $scope.opened = true;
    });
  };
});

lemur.service('DefaultService', function (LemurRestangular) {
  var DefaultService = this;
  DefaultService.get = function () {
    return LemurRestangular.all('defaults').customGET().then(function (defaults) {
      return defaults;
    });
  };
});

lemur.factory('LemurRestangular', function (Restangular, $location, $auth) {
  return Restangular.withConfig(function (RestangularConfigurer) {
    RestangularConfigurer.setBaseUrl('http://localhost:5000/api/1');
    RestangularConfigurer.setDefaultHttpFields({withCredentials: true});

    RestangularConfigurer.addResponseInterceptor(function (data, operation) {
      var extractedData;

      // .. to look for getList operations
      if (operation === 'getList') {
        // .. and handle the data and meta data
        extractedData = data.items;
        extractedData.total = data.total;
      } else {
        extractedData = data;
      }
      return extractedData;
    });

    RestangularConfigurer.addFullRequestInterceptor(function (element, operation, route, url, headers, params) {
      // We want to make sure the user is auth'd before any requests
      if (!$auth.isAuthenticated()) {
        $location.path('/login');
        return false;
      }

      var regExp = /\[([^)]+)\]/;

      var s = 'sorting';
      var f = 'filter';
      var newParams = {};
      for (var item in params) {
        if (item.indexOf(s) > -1) {
          newParams.sortBy = regExp.exec(item)[1];
          newParams.sortDir = params[item];
        } else if (item.indexOf(f) > -1) {
          var key = regExp.exec(item)[1];
          newParams.filter = key + ';' + params[item];
        } else {
          newParams[item] = params[item];
        }
      }
      return { params: newParams };
    });

  });
});

lemur.run(['$templateCache', function ($templateCache) {
  $templateCache.put('ng-table/pager.html', '<div class="ng-cloak ng-table-pager"> <div ng-if="params.settings().counts.length" class="ng-table-counts btn-group pull-left"> <button ng-repeat="count in params.settings().counts" type="button" ng-class="{\'active\':params.count()==count}" ng-click="params.count(count)" class="btn btn-default"> <span ng-bind="count"></span> </button></div><div class="pull-right"><ul style="margin: 0; padding: 0;" class="pagination ng-table-pagination"> <li ng-class="{\'disabled\': !page.active}" ng-repeat="page in pages" ng-switch="page.type"> <a ng-switch-when="prev" ng-click="params.page(page.number)" href="">&laquo;</a> <a ng-switch-when="first" ng-click="params.page(page.number)" href=""><span ng-bind="page.number"></span></a> <a ng-switch-when="page" ng-click="params.page(page.number)" href=""><span ng-bind="page.number"></span></a> <a ng-switch-when="more" ng-click="params.page(page.number)" href="">&#8230;</a> <a ng-switch-when="last" ng-click="params.page(page.number)" href=""><span ng-bind="page.number"></span></a> <a ng-switch-when="next" ng-click="params.page(page.number)" href="">&raquo;</a> </li> </ul> </div></div>');
}]);
