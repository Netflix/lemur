'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('notifications', {
      url: '/notifications',
      templateUrl: '/angular/notifications/view/view.tpl.html',
      controller: 'NotificationsViewController'
    });
  })

  .controller('NotificationsViewController', function ($q, $scope, $uibModal, NotificationApi, NotificationService, ngTableParams, toaster) {
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
            body: 'I see what you did there: ' + response.data.message
          });
        }
      );
    };

    $scope.edit = function (notificationId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/notifications/notification/notification.tpl.html',
        controller: 'NotificationsEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return notificationId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.notificationsTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'NotificationsCreateController',
        templateUrl: '/angular/notifications/notification/notification.tpl.html',
        size: 'lg',
        backdrop: 'static'
      });

      uibModalInstance.result.then(function () {
        $scope.notificationsTable.reload();
      });

    };

    $scope.notificationService = NotificationService;

  });
