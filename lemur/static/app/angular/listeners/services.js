'use strict';

angular.module('lemur')
  .service('ListenerApi', function (LemurRestangular) {
    return LemurRestangular.all('listeners');
  })
  .service('ListenerService', function ($location, ListenerApi) {
    var ListenerService = this;
    ListenerService.findListenerByName = function (filterValue) {
      return ListenerApi.getList({'filter[name]': filterValue})
        .then(function (roles) {
          return roles;
        });
    };

    ListenerService.create = function (role) {
      ListenerApi.post(role).then(function () {
        toaster.pop({
          type: 'success',
          title: 'Listener ' + role.name,
          body: 'Has been successfully created!'
        });
        $location.path('roles/view');
      });
    };

    ListenerService.update = function (role) {
      role.put().then(function () {
        toaster.pop({
          type: 'success',
          title: 'Listener ' + role.name,
          body: 'Has been successfully updated!'
        });
        $location.path('roles/view');
      });
    };
  });
