'use strict';

describe('Controller: CertificatesCtrl', function () {

  // load the controller's module
  beforeEach(module('lemurApp'));

  var CertificatesCtrl,
    scope;

  // Initialize the controller and a mock scope
  beforeEach(inject(function ($controller, $rootScope) {
    scope = $rootScope.$new();
    CertificatesCtrl = $controller('CertificatesCtrl', {
      $scope: scope
    });
  }));

  it('should attach a list of awesomeThings to the scope', function () {
    expect(scope.awesomeThings.length).toBe(3);
  });
});
