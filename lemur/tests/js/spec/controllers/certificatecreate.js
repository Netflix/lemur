'use strict';

describe('Controller: CertificatecreateCtrl', function () {

  // load the controller's module
  beforeEach(module('lemurApp'));

  var CertificatecreateCtrl,
    scope;

  // Initialize the controller and a mock scope
  beforeEach(inject(function ($controller, $rootScope) {
    scope = $rootScope.$new();
    CertificatecreateCtrl = $controller('CertificatecreateCtrl', {
      $scope: scope
    });
  }));

  it('should attach a list of awesomeThings to the scope', function () {
    expect(scope.awesomeThings.length).toBe(3);
  });
});
