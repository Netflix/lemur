'use strict';

angular.module('lemur')
  .service('ApiKeyApi', function (LemurRestangular) {
    return LemurRestangular.all('api_keys');
  })
  .service('ApiKeyService', function ($location, ApiKeyApi) {
    var ApiKeyService = this;
    ApiKeyService.update = function(apiKey) {
      return apiKey.put();
    };

    ApiKeyService.updateRevoked = function(apiKey) {
      return apiKey.put();
    };

    ApiKeyService.create = function (apiKey) {
      return ApiKeyApi.post(apiKey);
    };

    ApiKeyService.delete = function (apiKey) {
      return apiKey.remove();
    };
  });
