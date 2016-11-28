'use strict';

angular.module('lemur')
  .service('LogApi', function (LemurRestangular) {
    return LemurRestangular.all('logs');
  })
  .service('LogService', function () {
    var LogService = this;
    return LogService;
  });
