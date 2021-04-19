'use strict';

(function() {
  var lemur = angular
    .module('lemur', [
      'ui.router',
      'ngTable',
      'ngAnimate',
      'chart.js',
      'restangular',
      'angular-loading-bar',
      'ui.bootstrap',
      'toaster',
      'uiSwitch',
      'mgo-angular-wizard',
      'satellizer',
      'ngLetterAvatar',
      'angular-clipboard',
      'ngFileSaver',
      'ngSanitize',
      'ui.select'
    ]);


  function fetchData() {
    var initInjector = angular.injector(['ng']);
    var $http = initInjector.get('$http');

    return $http.get('http://localhost:8000/api/1/auth/providers').then(function(response) {
      lemur.constant('providers', response.data);
    }, function(errorResponse) {
      console.log('Could not fetch SSO providers' + errorResponse);
    });
  }

  function bootstrapApplication() {
    angular.element(document).ready(function() {
      angular.bootstrap(document, ['lemur']);
    });
  }

  fetchData().then(bootstrapApplication);

  lemur.config(function ($stateProvider, $urlRouterProvider, $authProvider, providers) {
    $urlRouterProvider.otherwise('/welcome');
    $stateProvider
      .state('welcome', {
        url: '/welcome',
        templateUrl: 'angular/welcome/welcome.html'
      });

    _.each(providers, function(provider) {
      if ($authProvider.hasOwnProperty(provider.name)) {
        $authProvider[provider.name](provider);
      } else {
        $authProvider.oauth2(provider);
      }
    });
  });

  lemur.directive('compareTo', function() {
    return {
        require: 'ngModel',
        scope: {
            otherModelValue: '=compareTo'
        },
        link: function(scope, element, attributes, ngModel) {

            ngModel.$validators.compareTo = function(modelValue) {
                return modelValue === scope.otherModelValue;
            };

            scope.$watch('otherModelValue', function() {
                ngModel.$validate();
            });
        }
    };
  });

  lemur.directive('confirmClick', function(){
    return {
      priority: -1,
      restrict: 'A',
      link: function(scope, element, attrs){
        element.bind('click', function(e){
          const message = attrs.confirmClick || 'Are you sure?';
          if(!window.confirm(message)){
            e.stopImmediatePropagation();
            e.preventDefault();
          }
        });
      }
    };
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

  lemur.service('DnsProviders', function (LemurRestangular) {
    var DnsProviders = this;
    DnsProviders.get = function () {
      return LemurRestangular.all('dns_providers').customGET().then(function (dnsProviders) {
        return dnsProviders;
      });
    };
  });

  lemur.directive('lemurBadRequest', [function () {
			return {
				template: '<h4>{{ directiveData.message }}</h4>' +
									'<div ng-repeat="(key, value) in directiveData.reasons">' +
										'<strong>{{ key | titleCase }}</strong> - {{ value }}</strong>' +
				          '</div>'
			};
		}]);

  lemur.factory('LemurRestangular', function (Restangular, $location, $auth) {
    return Restangular.withConfig(function (RestangularConfigurer) {
      RestangularConfigurer.setBaseUrl('http://localhost:8000/api/1');
      RestangularConfigurer.setDefaultHttpFields({withCredentials: true});

      // handle situation where our token has become invalid.
      RestangularConfigurer.setErrorInterceptor(function (response) {
        if (response.status === 401) {
          $auth.logout();
          $location.path('/login');
          return false;
        }
      });

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

  lemur.run(function ($templateCache, $location, $rootScope, $auth, $state) {
    $templateCache.put('ng-table/pager.html', '<div class="ng-cloak ng-table-pager"> <div ng-if="params.settings().counts.length" class="ng-table-counts btn-group pull-left"> <button ng-repeat="count in params.settings().counts" type="button" ng-class="{\'active\':params.count()==count}" ng-click="params.count(count)" class="btn btn-default"> <span ng-bind="count"></span> </button></div><div class="pull-right"><ul style="margin: 0; padding: 0;" class="pagination ng-table-pagination"> <li ng-class="{\'disabled\': !page.active}" ng-repeat="page in pages" ng-switch="page.type"> <a ng-switch-when="prev" ng-click="params.page(page.number)" href="">&laquo;</a> <a ng-switch-when="first" ng-click="params.page(page.number)" href=""><span ng-bind="page.number"></span></a> <a ng-switch-when="page" ng-click="params.page(page.number)" href=""><span ng-bind="page.number"></span></a> <a ng-switch-when="more" ng-click="params.page(page.number)" href="">&#8230;</a> <a ng-switch-when="last" ng-click="params.page(page.number)" href=""><span ng-bind="page.number"></span></a> <a ng-switch-when="next" ng-click="params.page(page.number)" href="">&raquo;</a> </li> </ul> </div></div>');
    $rootScope.$on('$stateChangeStart', function(event, toState, toParams) {
      if (toState.name !== 'login') {
        if (!$auth.isAuthenticated()) {
          event.preventDefault();
          $state.go('login', {'toState': toState.name, 'toParams': toParams, notify: false});
        }
      }
    });
  });
}());


