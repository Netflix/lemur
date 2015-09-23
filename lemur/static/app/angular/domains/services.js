'use strict';

angular.module('lemur')
  .service('DomainApi', function (LemurRestangular) {
    return LemurRestangular.all('domains');
  })
  .service('DomainService', function ($location, DomainApi) {
    var DomainService = this;
    DomainService.findDomainByName = function (filterValue) {
      return DomainApi.getList({'filter[name]': filterValue})
        .then(function (domains) {
          return domains;
        });
    };
  });
