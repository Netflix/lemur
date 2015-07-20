angular.module('lemur')
    .service('PluginApi', function (LemurRestangular) {
        return LemurRestangular.all('plugins');
    })
    .service('PluginService', function (PluginApi) {
        var PluginService = this;
        PluginService.get = function (type) {
           return PluginApi.customGETLIST(type).then(function (plugins) {
              return plugins;
           });
        };
    });
