'use strict';

angular.module('lemur')

  .controller('NotificationsCreateController', function ($scope, $modalInstance, PluginService, NotificationService, CertificateService, LemurRestangular){
    $scope.notification = LemurRestangular.restangularizeElement(null, {}, 'notifications');

    PluginService.getByType('notification').then(function (plugins) {
      $scope.plugins = plugins;
    });
    $scope.save = function (notification) {
      NotificationService.create(notification).then(
        function () {
          $modalInstance.close();
        },
        function () {

        }
      );
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.certificateService = CertificateService;
  })

  .controller('NotificationsEditController', function ($scope, $modalInstance, NotificationService, NotificationApi, PluginService, CertificateService, editId) {
    NotificationApi.get(editId).then(function (notification) {
      $scope.notification = notification;
      NotificationService.getCertificates(notification);
    });

    PluginService.getByType('notification').then(function (plugins) {
      $scope.plugins = plugins;
      _.each($scope.plugins, function (plugin) {
        if (plugin.slug == $scope.notification.pluginName) {
          plugin.pluginOptions = $scope.notification.notificationOptions;
          $scope.notification.plugin = plugin;
        };
      });
    });

    $scope.save = function (notification) {
      NotificationService.update(notification).then(function () {
        $modalInstance.close();
      });
    };

    $scope.cancel = function () {
      $modalInstance.dismiss('cancel');
    };

    $scope.certificateService = CertificateService;
  });
