"""
.. module: lemur.analyze.service
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
#def analyze(endpoints, truststores):
#    results = {"headings": ["Endpoint"],
#               "results": [],
#               "time": datetime.now().strftime("#Y%m%d %H:%M:%S")}
#
#    for store in truststores:
#        results['headings'].append(os.path.basename(store))
#
#    for endpoint in endpoints:
#        result_row = [endpoint]
#        for store in truststores:
#            result = {'details': []}
#
#            tests = []
#            for region, ip in REGIONS.items():
#                try:
#                    domain = dns.name.from_text(endpoint)
#                    if not domain.is_absolute():
#                        domain = domain.concatenate(dns.name.root)
#
#                    my_resolver = dns.resolver.Resolver()
#                    my_resolver.nameservers = [ip]
#                    answer = my_resolver.query(domain)
#
#                    #force the testing of regional enpoints by changing the dns server
#                    response = requests.get('https://' + str(answer[0]), verify=store)
#                    tests.append('pass')
#                    result['details'].append("{}: SSL testing completed without errors".format(region))
#
#                except SSLError as e:
#                    log.debug(e)
#                    if 'hostname' in str(e):
#                        tests.append('pass')
#                        result['details'].append("{}: This test passed ssl negotiation but failed hostname verification becuase the hostname is not included in the certificate".format(region))
#                    elif 'certificate verify failed' in str(e):
#                        tests.append('fail')
#                        result['details'].append("{}: This test failed to verify the SSL certificate".format(region))
#                    else:
#                        tests.append('fail')
#                        result['details'].append("{}: {}".format(region, str(e)))
#
#                except Exception as e:
#                    log.debug(e)
#                    tests.append('fail')
#                    result['details'].append("{}: {}".format(region, str(e)))
#
#            #any failing tests fails the whole endpoint
#            if 'fail' in tests:
#                result['test'] = 'fail'
#            else:
#                result['test'] = 'pass'
#
#            result_row.append(result)
#        results['results'].append(result_row)
#    return results
#
