'use strict';
angular.module('lemur')
  .service('NotificationApi', function (LemurRestangular) {
    LemurRestangular.extendModel('notifications', function (obj) {
      return angular.extend(obj, {
        attachCertificate: function (certificate) {
          this.selectedCertificate = null;
          if (this.certificates === undefined) {
            this.certificates = [];
          }
          this.certificates.push(certificate);
        },
        removeCertificate: function (index) {
          this.certificate.splice(index, 1);
        }
      });
    });
    return LemurRestangular.all('notifications');
  })
  .service('NotificationService', function ($location,  NotificationApi, PluginService, toaster) {
    var NotificationService = this;
    NotificationService.findNotificationsByName = function (filterValue) {
      return NotificationApi.getList({'filter[label]': filterValue})
        .then(function (notifications) {
          return notifications;
        });
    };

    NotificationService.getCertificates = function (notification) {
      notification.getList('certificates').then(function (certificates) {
        notification.certificates = certificates;
      });
    };

    NotificationService.getPlugin = function (notification) {
      return PluginService.getByName(notification.pluginName).then(function (plugin) {
        notification.plugin = plugin;
      });
    };


    NotificationService.loadMoreCertificates = function (notification, page) {
      notification.getList('certificates', {page: page}).then(function (certificates) {
        _.each(certificates, function (certificate) {
          notification.roles.push(certificate);
        });
      });
    };

    NotificationService.create = function (notification) {
      return NotificationApi.post(notification).then(
        function () {
          toaster.pop({
            type: 'success',
            title: notification.label,
            body: 'Successfully created!'
          });
          $location.path('notifications');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: notification.label,
            body: 'Was not created! ' + response.data.message
          });
        });
    };

    NotificationService.update = function (notification) {
      return notification.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: notification.label,
            body: 'Successfully updated!'
          });
          $location.path('notifications');
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: notification.label,
            body: 'Was not updated! ' + response.data.message
          });
        });
    };

    NotificationService.updateActive = function (notification) {
      notification.put().then(
        function () {
          toaster.pop({
            type: 'success',
            title: notification.name,
            body: 'Successfully updated!'
          });
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: notification.name,
            body: 'Was not updated! ' + response.data.message
          });
        });
    };
    return NotificationService;
  });
