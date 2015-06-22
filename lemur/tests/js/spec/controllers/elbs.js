'use strict';

describe('Controller: ElbsCtrl', function () {

  // load the controller's module
  beforeEach(module('lemurApp'));

  var ElbsCtrl,
    scope;

  // Initialize the controller and a mock scope
  beforeEach(inject(function ($controller, $rootScope) {
    scope = $rootScope.$new();
    ElbsCtrl = $controller('ElbsCtrl', {
      $scope: scope
    });
  }));

  it('should attach a list of awesomeThings to the scope', function () {
    expect(scope.awesomeThings.length).toBe(3);
  });
});
