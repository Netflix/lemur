'use strict';

angular.module('lemur')

  .config(function config($routeProvider) {
    $routeProvider.when('/notifications', {
      templateUrl: '/angular/notifications/view/view.tpl.html',
      controller: 'NotificationsViewController'
    });
  })

  .controller('NotificationsViewController', function ($q, $scope, $modal, NotificationApi, NotificationService, ngTableParams, toaster) {
    $scope.filter = {};
    $scope.notificationsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        NotificationApi.getList(params.url()).then(
          function (data) {
            _.each(data, function (notification) {
              NotificationService.getPlugin(notification);
            });
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });

    $scope.getNotificationStatus = function () {
      var def = $q.defer();
      def.resolve([{'title': 'Active', 'id': true}, {'title': 'Inactive', 'id': false}]);
      return def;
    };

    $scope.remove = function (notification) {
      notification.remove().then(
        function () {
          $scope.notificationsTable.reload();
        },
        function (response) {
          toaster.pop({
            type: 'error',
            title: 'Opps',
            body: 'I see what you did there' + response.data.message
          });
        }
      );
    };

    $scope.edit = function (notificationId) {
      var modalInstance = $modal.open({
        animation: true,
        templateUrl: '/angular/notifications/notification/notification.tpl.html',
        controller: 'NotificationsEditController',
        size: 'lg',
        resolve: {
          editId: function () {
            return notificationId;
          }
        }
      });

      modalInstance.result.then(function () {
        $scope.notificationsTable.reload();
      });

    };

    $scope.create = function () {
      var modalInstance = $modal.open({
        animation: true,
        controller: 'NotificationsCreateController',
        templateUrl: '/angular/notifications/notification/notification.tpl.html',
        size: 'lg'
      });

      modalInstance.result.then(function () {
        $scope.notificationsTable.reload();
      });

    };

    $scope.toggleFilter = function (params) {
      params.settings().$scope.show_filter = !params.settings().$scope.show_filter;
    };

    $scope.notificationService = NotificationService;

  });
