'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('expiring_reports', {
      url: '/expiring_reports',
      templateUrl: '/angular/reports/expiring/view/view.tpl.html',
      controller: 'ExpiringReportsViewController'
    });
  })

   .controller('ExpiringReportsViewController', function ($scope, LemurRestangular, ngTableParams, CertificateApi, MomentService) {
     $scope.showFilters = false;
     $scope.momentService = MomentService;
     $scope.daysFilters = [
       {count: 1, label:'In 1 Day'},
       {count: 3, label:'In 3 Days'},
       {count: 7, label:'In 7 Days'},
       {count: 30, label:'In next Month'},
       {count: 60, label:'In 2 Months'},
       {count: 900, label:'In 3 Months'}
     ];
     $scope.filters = [
       {sortable: 'id', show: false, title:'Id', field:'id'},
       {sortable: 'name', show: true, title:'Name', field:'name'},
       {sortable: 'cn', show: false, title:'Common Name', field:'cn'},
       {sortable: 'notify', show: false, title:'Notify', field:'notify', type:'boolean'},
       {sortable: 'serial', show: false, title:'Serial', field:'serial'},
       {sortable: 'creator', show: true, title:'Creator', field:'creator'},
       {sortable: 'owner', show: true, title:'Owner', field:'owner'},
       {sortable: 'notBefore', show: false, title:'Valid From', field:'notBefore', type:'Date'},
       {sortable: 'notAfter', show: true, title:'Valid To', field:'notAfter', type:'Date'},
       {sortable: 'san', show: true, title:'SAN', field:'san', type:'boolean'},
       {sortable: 'bits', show: true, title:'Key Length', field:'bits'},
       {sortable: 'keyType', show: true, title:'Key type', field:'keyType'},
       {sortable: 'signingAlgorithm', show: true, title:'Signing Algorithm', field:'signingAlgorithm'},
       {sortable: 'status', show: true, title:'Validity', field:'status'},
     ];

     $scope.filterData = function (days, from, to) {
       $scope.expiresInDays = days;
       $scope.data=[];
       if (days) {
         const now = new Date();
         from = now.toISOString().substr(0,10);
         now.setDate(now.getDate() + $scope.expiresInDays);
         to = now.toISOString().substr(0,10);
       } else {
         from = from?from.toISOString().substr(0,10):'*';
         to = to?to.toISOString().substr(0,10):'*';
       }
       const notAfterRange = `${from}to${to}`;
       LemurRestangular.all('certificates').customGET('stats', {metric: 'issuer', notAfterRange})
         .then(function (data) {
           $scope.issuers = data.items;
         });

       LemurRestangular.all('certificates').customGET('stats', {metric: 'bits', notAfterRange})
         .then(function (data) {
           $scope.bits = data.items;
         });

      LemurRestangular.all('certificates').customGET('stats', {metric: 'signing_algorithm', notAfterRange})
        .then(function (data) {
          $scope.algos = data.items;
        });

       LemurRestangular.all('destinations').customGET('stats', {metric: 'destinations', notAfterRange})
         .then(function (data) {
           $scope.destinations = data.items;
         });
         $scope.certificateTable = new ngTableParams({
           page: 1,            // sortable: '', show first page
           count: 10,          // count per page
           sorting: {
             id: 'desc'     // initial sorting
           },
           short: true
         }, {
           total: 0,           // length of data
           getData: function ($defer, params) {
             const url = params.url();
             url['filter[notAfterRange]'] = notAfterRange;
             CertificateApi.getList(url)
               .then(function (data) {
                 params.total(data.total);
                 $defer.resolve(data);
               });
           }
         });
     };
     $scope.toggleFilter = function (filter) {
       filter.show = !filter.show;
     };
     $scope.showFilterOptions = function() {
       $scope.showFilters = !$scope.showFilters;
     };
     $scope.filterData(30);
   });
