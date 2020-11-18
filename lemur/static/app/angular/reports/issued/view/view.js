'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('issued_reports', {
      url: '/issued_reports',
      templateUrl: '/angular/reports/issued/view/view.tpl.html',
      controller: 'IssuedReportsViewController'
    });
  })

   .controller('IssuedReportsViewController', function () {

   });
