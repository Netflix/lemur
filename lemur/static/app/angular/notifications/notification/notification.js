'use strict';

angular.module('lemur')

  .controller('NotificationsCreateController', function ($scope, $uibModalInstance, PluginService, NotificationService, CertificateService, LemurRestangular, toaster){
    $scope.notification = LemurRestangular.restangularizeElement(null, {}, 'notifications');

    PluginService.getByType('notification').then(function (plugins) {
      $scope.plugins = plugins;
    });
    $scope.save = function (notification) {
      NotificationService.create(notification).then(
        function () {
          toaster.pop({
            type: 'success',
            title: notification.label,
            body: 'Successfully Created!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: notification.label,
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });
        });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };

    $scope.certificateService = CertificateService;
  })

  .controller('NotificationsEditController', function ($scope, $uibModalInstance, NotificationService, NotificationApi, PluginService, CertificateService, toaster, editId) {
    NotificationApi.get(editId).then(function (notification) {
      $scope.notification = notification;
      PluginService.getByType('notification').then(function (plugins) {
        $scope.plugins = plugins;
        _.each($scope.plugins, function (plugin) {
          if (plugin.slug === $scope.notification.plugin.slug) {
            plugin.pluginOptions = $scope.notification.plugin.pluginOptions;
            $scope.notification.plugin = plugin;
          }
        });
      });
      NotificationService.getCertificates(notification);
    });

    $scope.save = function (notification) {
      NotificationService.update(notification).then(
        function () {
          toaster.pop({
            type: 'success',
            title: notification.label,
            body: 'Successfully Updated!'
          });
          $uibModalInstance.close();
        }, function (response) {
          toaster.pop({
            type: 'error',
            title: notification.label,
            body: 'lemur-bad-request',
            bodyOutputType: 'directive',
            directiveData: response.data,
            timeout: 100000
          });
        });
    };

    $scope.cancel = function () {
      $uibModalInstance.dismiss('cancel');
    };

    $scope.certificateService = CertificateService;
  });
