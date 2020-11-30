'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('issued_reports', {
      url: '/issued_reports',
      templateUrl: '/angular/reports/issued/view/view.tpl.html',
      controller: 'IssuedReportsViewController'
    });
  })

   .controller('IssuedReportsViewController', function ($scope, LemurRestangular, ngTableParams, CertificateApi, MomentService) {
     $scope.showFilters = false;
     $scope.momentService=MomentService;
     $scope.daysFilters = [
       {count: 1, label:'Last Day'},
       {count: 3, label:'Within 3 Days'},
       {count: 7, label:'Within 7 Days'},
       {count: 30, label:'Within Last Month'},
       {count: 60, label:'Within 2 Months'},
       {count: 90, label:'Within 3 Months'}
     ];
     $scope.filters = [
       {sortable: 'id', show: false, title:'Id', field:'id'},
       {sortable: 'name', show: true, title:'Name', field:'name'},
       {sortable: 'cn', show: false, title:'Common Name', field:'cn'},
       {sortable: 'notify', show: false, title:'Notify', field:'notify', type:'boolean'},
       {sortable: 'serial', show: false, title:'Serial', field:'serial'},
       {sortable: 'creator', show: true, title:'Creator', field:'creator'},
       {sortable: 'owner', show: true, title:'Owner', field:'owner'},
       {sortable: 'notBefore', show: true, title:'Valid From', field:'notBefore', type:'Date'},
       {sortable: 'notAfter', show: false, title:'Valid To', field:'notAfter', type:'Date'},
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
         to = now.toISOString().substr(0,10);
         now.setDate(now.getDate() - $scope.expiresInDays);
         from = now.toISOString().substr(0,10);
       } else {
         from = from?from.toISOString().substr(0,10):'*';
         to = to?to.toISOString().substr(0,10):'*';
       }
       const notBeforeRange = `${from}to${to}`;
       LemurRestangular.all('certificates').customGET('stats', {metric: 'issuer', notBeforeRange})
         .then(function (data) {
           $scope.issuers = data.items;
         });

       LemurRestangular.all('certificates').customGET('stats', {metric: 'bits', notBeforeRange})
         .then(function (data) {
           $scope.bits = data.items;
         });

      LemurRestangular.all('certificates').customGET('stats', {metric: 'signing_algorithm', notBeforeRange})
        .then(function (data) {
          $scope.algos = data.items;
        });

       LemurRestangular.all('destinations').customGET('stats', {metric: 'destinations', notBeforeRange})
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
             url['filter[notBeforeRange]'] = notBeforeRange;
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
