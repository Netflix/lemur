'use strict';

angular.module('lemur')
  .service('PolicesApi', function (LemurRestangular) {
    return LemurRestangular.all('polices');
  })
  .service('PolicesService', function ($location, PolicesApi) {
    var PolicesService = this;
    PolicesService.findPoliceByName = function (filterValue) {
      return PolicesApi.getList({'filter[name]': filterValue})
        .then(function (polices) {
          return polices;
        });
    };

    PolicesService.create = function (polices) {
      return PolicesApi.post(polices);
    };

    PolicesService.update = function (polices) {
      return polices.put();
    };
  });