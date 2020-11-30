'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('reports', {
      url: '/reports',
      templateUrl: '/angular/reports/generic/view/view.tpl.html',
      controller: 'ReportsViewController'
    });
  })

   .controller('ReportsViewController', function ($scope, LemurRestangular, CertificateApi) {
    $scope.classes=['panel-primary',
    'panel-success',
    'panel-warning',
    'panel-default',
    'panel-default',
    'panel-default'];
    $scope.reports=[
      {label:'Issuer', value:'issuer'},
      {label:'Key Length', value:'bits'},
      {label:'Signing Algorithm', value:'signing_algorithm'},
      {label:'Key Type', value:'key_type'},
      {label:'Common Name', value:'cn'}
    ];
    $scope.updateReport= function (report) {
      if (report.value && report.value !== $scope.selectedReport.value) {
        $scope.selectedReport = report;
        LemurRestangular.all('certificates').customGET('stats', {metric: report.value})
           .then(function (data) {
             $scope.data = data.items;
           });
      } else {
        $scope.selectedReport = {};
        $scope.data = {labels:[],values:[]};
        CertificateApi.getList({showExpired:1})
          .then(function (data) {
            $scope.data.labels.push('total');
            $scope.data.values.push(data.total);
          });
        CertificateApi.getList({showExpired:0})
          .then(function (data) {
            $scope.data.labels.push('Not Expired');
            $scope.data.values.push(data.total);
          });
        const date = new Date();
        const now = date.toISOString().substr(0,10);
        date.setDate(date.getDate() + 30);
        const afterMonth = date.toISOString().substr(0,10);
        date.setDate(date.getDate() - 60);
        const beforeMonth = date.toISOString().substr(0,10);

        CertificateApi.getList({'filter[notAfterRange]':`${now}to${afterMonth}`})
          .then(function (data) {
            $scope.data.labels.push('Expiring in 30 days');
            $scope.data.values.push(data.total);
          });
        CertificateApi.getList({'filter[notAfterRange]':`${beforeMonth}to${now}`})
          .then(function (data) {
            $scope.data.labels.push('Issued last 30 days');
            $scope.data.values.push(data.total);
          });
      }
    };
    $scope.updateReport({});
   })
   ;
