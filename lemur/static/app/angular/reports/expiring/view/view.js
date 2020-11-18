'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('expiring_reports', {
      url: '/expiring_reports',
      templateUrl: '/angular/reports/expiring/view/view.tpl.html',
      controller: 'ExpiringReportsViewController'
    });
  })

   .controller('ExpiringReportsViewController', function () {



   });
