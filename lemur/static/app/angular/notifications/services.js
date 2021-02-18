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
          this.certificates.splice(index, 1);
        }
      });
    });
    return LemurRestangular.all('notifications');
  })
  .service('NotificationService', function ($location,  NotificationApi, PluginService) {
    var NotificationService = this;
    NotificationService.findNotificationsByName = function (filterValue) {
      return NotificationApi.getList({'filter[label]': filterValue})
        .then(function (notifications) {
          return notifications;
        });
    };

    NotificationService.getCertificates = function (notification) {
      notification.getList('certificates', {showExpired: 0}).then(function (certificates) {
        notification.certificates = certificates;
      });
    };

    NotificationService.getPlugin = function (notification) {
      return PluginService.getByName(notification.pluginName).then(function (plugin) {
        notification.plugin = plugin;
      });
    };


    NotificationService.loadMoreCertificates = function (notification, page) {
      notification.getList('certificates', {page: page, showExpired: 0}).then(function (certificates) {
        _.each(certificates, function (certificate) {
          notification.certificates.push(certificate);
        });
      });
    };

    NotificationService.create = function (notification) {
      return NotificationApi.post(notification);
    };

    NotificationService.update = function (notification) {
      return notification.put();
    };

    NotificationService.updateActive = function (notification) {
      notification.put();
    };
    return NotificationService;
  });
