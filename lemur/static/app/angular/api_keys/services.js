'use strict';

angular.module('lemur')
  .service('ApiKeyApi', function (LemurRestangular) {
    LemurRestangular.extendModel('keys', function (obj) {
      return angular.extend(obj, {
        attachUser: function (user) {
          this.user = user;
        }
      });
    });
    return LemurRestangular.all('keys');
  })
  .service('ApiKeyService', function ($location, ApiKeyApi) {
    var ApiKeyService = this;

    ApiKeyService.update = function(apiKey) {
      return apiKey.put();
    };

    ApiKeyService.create = function (apiKey) {
      return ApiKeyApi.post(apiKey);
    };

    ApiKeyService.delete = function (apiKey) {
      return apiKey.remove();
    };
  });
