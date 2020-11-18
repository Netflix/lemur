'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('reports', {
      url: '/reports',
      templateUrl: '/angular/reports/generic/view/view.tpl.html',
      controller: 'ReportsViewController'
    });
  })

   .controller('ReportsViewController', function () {

   });
