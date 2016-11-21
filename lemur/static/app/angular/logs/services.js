'use strict';

angular.module('lemur')
  .service('LogApi', function (LemurRestangular) {
    return LemurRestangular.all('domains');
  })
  .service('LogService', function () {
    var LogService = this;
    return LogService;
  });
