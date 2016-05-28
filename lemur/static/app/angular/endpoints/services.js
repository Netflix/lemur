'use strict';
angular.module('lemur')
  .service('EndpointApi', function (LemurRestangular) {
    return LemurRestangular.all('endpoints');
  })
  .service('EndpointService', function ($location,  EndpointApi) {
    var EndpointService = this;
    EndpointService.findEndpointsByName = function (filterValue) {
      return EndpointApi.getList({'filter[label]': filterValue})
        .then(function (endpoints) {
          return endpoints;
        });
    };

    EndpointService.getCertificates = function (endpoint) {
      endpoint.getList('certificates').then(function (certificates) {
        endpoint.certificates = certificates;
      });
    };
    return EndpointService;
  });
