'use strict';
angular.module('lemur')
  .service('DestinationApi', function (LemurRestangular) {
    return LemurRestangular.all('destinations');
  })
  .service('DestinationService', function ($location,  DestinationApi, toaster) {
    var DestinationService = this;
    DestinationService.findDestinationsByName = function (filterValue) {
      return DestinationApi.getList({'filter[label]': filterValue})
        .then(function (destinations) {
          return destinations;
        });
    };

    DestinationService.create = function (destination) {
      return DestinationApi.post(destination).then(
        function () {
          toaster.pop({
            type: 'success',
            title: destination.label,
            body: 'Successfully created!'
          });
          $location.path('destinations');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: destination.label,
            body: 'Was not created! ' + response.data.message
          });
        });
    };

    DestinationService.update = function (destination) {
      return destination.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: destination.label,
            body: 'Successfully updated!'
          });
          $location.path('destinations');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: destination.label,
            body: 'Was not updated! ' + response.data.message
          });
        });
    };
    return DestinationService;
  });
