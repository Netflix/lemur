'use strict';
angular.module('lemur')
  .service('ReportApi', function (LemurRestangular) {
    return LemurRestangular.all('reports');
  })

  .service('ReportOptions', function (LemurRestangular) {
    return LemurRestangular.all('report_options');
  })

  .service('ReportService', function () {
    var ReportService = this;

    return ReportService;
  });
