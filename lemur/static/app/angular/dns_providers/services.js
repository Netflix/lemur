'use strict';
angular.module('lemur')
  .service('DnsProviderApi', function (LemurRestangular) {
    return LemurRestangular.all('dns_providers');
  })

  .service('DnsProviderOptions', function (LemurRestangular) {
    return LemurRestangular.all('dns_provider_options');
  })

  .service('DnsProviderService', function ($location,  DnsProviderApi, PluginService, DnsProviders, DnsProviderOptions) {
    var DnsProviderService = this;
    DnsProviderService.findDnsProvidersByName = function (filterValue) {
      return DnsProviderApi.getList({'filter[label]': filterValue})
        .then(function (dns_providers) {
          return dns_providers;
        });
    };

    DnsProviderService.getDnsProviders = function () {
      return DnsProviders.get();
    };

    DnsProviderService.getDnsProviderOptions = function () {
      return DnsProviderOptions.getList();
    };

    DnsProviderService.create = function (dns_provider) {
      return DnsProviderApi.post(dns_provider);
    };

    DnsProviderService.get = function () {
      return DnsProviderApi.get();
    };


    DnsProviderService.update = function (dns_provider) {
      return dns_provider.put();
    };

    DnsProviderService.getPlugin = function (dns_provider) {
      return PluginService.getByName(dns_provider.pluginName).then(function (plugin) {
        dns_provider.plugin = plugin;
      });
    };
    return DnsProviderService;
  });
