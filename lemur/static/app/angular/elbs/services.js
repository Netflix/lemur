'use strict';

angular.module('lemur')
  .service('ELBApi', function (LemurRestangular) {
    LemurRestangular.extendModel('elbs', function (obj) {
      return angular.extend(obj, {
        attachListener: function (listener) {
          if (this.listeners === undefined) {
            this.listeners = [];
          }
          this.listeners.push(listener);
        },
        removeListener: function (index) {
          this.listeners.splice(index, 1);
        }
      });
    });
    return LemurRestangular.all('elbs');
  })
  .service('ELBService', function ($location, ELBApi, toaster) {
    var ELBService = this;
    ELBService.findELBByName = function (filterValue) {
      return ELBApi.getList({'filter[name]': filterValue})
        .then(function (elbs) {
          return elbs;
        });
    };

    ELBService.getListeners = function (elb) {
      elb.getList('listeners').then(function (listeners) {
        elb.listeners = listeners;
      });
      return elb;
    };

    ELBService.create = function (elb) {
      ELBApi.post(elb).then(function () {
        toaster.pop({
          type: 'success',
          title: 'ELB ' + elb.name,
          body: 'Has been successfully created!'
        });
        $location.path('elbs');
      });
    };

    ELBService.update = function (elb) {
      elb.put().then(function () {
        toaster.pop({
          type: 'success',
          title: 'ELB ' + elb.name,
          body: 'Has been successfully updated!'
        });
        $location.path('elbs');
      });
    };

    return ELBService;
  });
