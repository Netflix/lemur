'use strict';

angular.module('lemur').
  filter('titleCase', function () {
    return function (str) {
      return (str === undefined || str === null) ? '' : str.replace(/([A-Z])/g, ' $1').replace(/^./, function (txt) {
        return txt.toUpperCase();
      });
    };
  });

