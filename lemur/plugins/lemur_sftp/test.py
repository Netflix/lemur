from plugin import SFTPDestinationPlugin
from flask import Flask


args = {
 'name': 'test.com-testcom',
 'options':
    [
        {
            'name': 'host',
            'value': '10.2.80.4'
        },
        {
            'name': 'port',
            'value': '22'
        },
        {
            'name': 'user',
            'value': 'root'
        },
        {
            'name': 'password',
            'value': None
        },
        {
            'name': 'privateKeyPath',
            'value': '/Users/dmitry/tmp/id_rsa'
        },
        {
            'name': 'privateKeyPass',
            'value': 'password'
        },
        {
            'name': 'destinationPath',
            'value': '/etc/nginx/certs'
        },
        {
            'name': 'destinationType',
            'value': 'NGINX'

        }
    ],
 'body': '-----BEGIN CERTIFICATE-----\n'
         'MIIC4jCCAcoCCQDxH4WYUD3PUzANBgkqhkiG9w0BAQsFADAzMQswCQYDVQQGEwJV\n'
         'UzERMA8GA1UECgwIdGVzdC5jb20xETAPBgNVBAMMCHRlc3QuY29tMB4XDTE4MDMy\n'
         'NjE2NDYwOFoXDTE5MDMyNjE2NDYwOFowMzELMAkGA1UEBhMCVVMxETAPBgNVBAoM\n'
         'CHRlc3QuY29tMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\n'
         'ggEPADCCAQoCggEBAMvBI3tvxs5BRGUlYTNNmQ10c6ds/1LSARW8qqjRKeARJvs7\n'
         'uO9f+unXrDxmNGZ9wiPXekAe9k0Qx9wgQ1JCHjPg/uHrNgCTwMc9P07P82L0N339\n'
         'LUx4OozNJ3eZlo8b/VE8/ToJcOAc/hR2DH2NPpdFB8wcljFS4do/FprCfOebMoaT\n'
         'Ef6Rr3WDsNX8TDx3mx37+1sNyjFQ0F/YHS0gF0LF99VHzuSXMxB1UOLtUTNqhuEV\n'
         'IWY+XLFBH+tEaumNXKYQTzHhI7uukIfR285a5zv1eOBs6XsYInlkfd4VIx70CYcT\n'
         'zP56V6lQC7L5UbeYklwcaF0mZL++QBjyb1e14ucCAwEAATANBgkqhkiG9w0BAQsF\n'
         'AAOCAQEAtaOiX9ersbunQc5lQnDSQuQqmR7+CmCTpJFSTkc1PEu3r421AZtU0S0S\n'
         'EjoQEPmnkuL0yVWr473AjbcgPoWPl7hLXXu1iAW31me2JIZLsSBF3hOt6sZDsjyd\n'
         'O0ZfdfijchXC25RfNW+9igF2HPyq+UkZgZq5/MsbpZKmKpsTaPaxZRv7dSXzYinT\n'
         'J4i0wi+9f9E1ezPlPvbEgIWjk1nQqerhhaExteMVS/eXq5mjC4mr83B0HNJeH4mX\n'
         'ZWqFjr5AbflTnGv9oFayWZcEST+IlkjT0l7iRp9ptgBwHerfUZs2XT7foydeRWWF\n'
         '4bdb6WHxX+vwj0kL5m2f180CA8agew==\n'
         '-----END CERTIFICATE-----',
 'private_key': b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC'
                b'BKcwggSjAgEAAoIBAQDLwSN7b8bOQURl\nJWEzTZkNdHOnbP9S0gEVvKqo0Sn'
                b'gESb7O7jvX/rp16w8ZjRmfcIj13pAHvZNEMfc\nIENSQh4z4P7h6zYAk8DHPT'
                b'9Oz/Ni9Dd9/S1MeDqMzSd3mZaPG/1RPP06CXDgHP4U\ndgx9jT6XRQfMHJYxU'
                b'uHaPxaawnznmzKGkxH+ka91g7DV/Ew8d5sd+/tbDcoxUNBf\n2B0tIBdCxffV'
                b'R87klzMQdVDi7VEzaobhFSFmPlyxQR/rRGrpjVymEE8x4SO7rpCH\n0dvOWuc'
                b'79XjgbOl7GCJ5ZH3eFSMe9AmHE8z+elepUAuy+VG3mJJcHGhdJmS/vkAY\n8m'
                b'9XteLnAgMBAAECggEASA0RRgodzDvqOrZALAspr0dZyn/RvfDDL3ObCb2FSF'
                b'Xo\nafkRiZxwNxbsMiOWLhQUfeYptdj9Ef14H1BNXh5BXekXWL57RzL4fbwb0'
                b'fvZPknM\nAcJwrVTqp3W4miN2yT6Fkp+1kDtcbfPyqTuhaRh0ZLulaTlGp0R+'
                b'11Vt4eYaky99\nqobPgi55v+79qFQRivuKUAoG4ut3zGzqKl5CZkVZzgVZmjQ'
                b'kUoiwurHZ5j2vNnyX\nvChjlYICFiEJAID4AdTeQd1SBDWYfum2w9HhlDLcPC'
                b'ut4mKG7CYevneNjn2y1JvX\nSfoQnG7QoFQ2wXAPIj6553utw/Qk1uS0u7Xdv'
                b'YbnIQKBgQDw1LEwsHd9k+M8o7jS\n/61SmTt3m19mfBmpXeP8eTiypLsMV1Hq'
                b'Sh7RyPmwMe2tkwiHEW/t2IR91TiUUTzK\ngrt6qeobB87e0zP4OaqDtymI2j7'
                b'gTgfZEOjoSjXDRVdZ96Djhzr+d4pqBSvXFTe7\nYF0TRKYuXhgoLqAo1+FucI'
                b'Wq0QKBgQDYlpqCTmaXqII/HWwMYsRIJcskX/XaBuJx\nMSlDcBIen5OOiqfYL'
                b'gcYrZmwfJlgtKILM+PQrbW4udJF4cmVnI0Eww4c5+WRVRtS\ny6fUzayelTwL'
                b'+QWvrJKiiHTGFZtclhoBsSMymhNuQ4JofnEWAB9FcwTVKGziYj3g\nGyM2y0c'
                b'wNwKBgQCHTqii93KbHnzcdAwCmF3z+1267JOkC/OLAdJ25lChpgXlgCXo\n4W'
                b'4BZc5LXTHxhJuU74oYcr61yBc61Y23Jc5Zs59xQmjLLpSTUSrpR/5RAnWzJo'
                b'Qo\nQ+TnpdIg/RN/264MR80wbU9aE7+23xfp8dE5YyePA5TE9rVLXUct+pBPE'
                b'QKBgFGe\nh4FdfCngtZyFQOd1/NPXcjM1+lb8Sy8uwIcKX7mslxWbSN8dkU0K'
                b'dqVcfwxDZeFk\n35APNjDzzbrJ+IZp5XaK7vGTrh5TfSV5W7jE/S0RvfwhDrS'
                b'CCww28hKHp/F/GzPS\nBhqWl4Xw6N7p70HEMASi8IpHXqj9LqYac+29MwmHAo'
                b'GABsaXLyhpS/arsZ8+GZAm\nPZRIphrGi5FWQqRgILD8ZdYPgshGQacKwG/Zn'
                b'tMfcTH6XyPO9isImwkUy+3CXWSv\n7Bswb0JB3ZQrn+khcuyrz+clAU4iUIba'
                b'y9aociiULBM3KwMGDo8WfQmFonbGrcC/\nsWhW/ndBhTqX1f1yQViIDqg'
                b'=\n-----END PRIVATE KEY-----',
 'cert_chain': '-----BEGIN CERTIFICATE-----\n'
         'MIIC4jCCAcoCCQDxH4WYUD3PUzANBgkqhkiG9w0BAQsFADAzMQswCQYDVQQGEwJV\n'
         'UzERMA8GA1UECgwIdGVzdC5jb20xETAPBgNVBAMMCHRlc3QuY29tMB4XDTE4MDMy\n'
         'NjE2NDYwOFoXDTE5MDMyNjE2NDYwOFowMzELMAkGA1UEBhMCVVMxETAPBgNVBAoM\n'
         'CHRlc3QuY29tMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\n'
         'ggEPADCCAQoCggEBAMvBI3tvxs5BRGUlYTNNmQ10c6ds/1LSARW8qqjRKeARJvs7\n'
         'uO9f+unXrDxmNGZ9wiPXekAe9k0Qx9wgQ1JCHjPg/uHrNgCTwMc9P07P82L0N339\n'
         'LUx4OozNJ3eZlo8b/VE8/ToJcOAc/hR2DH2NPpdFB8wcljFS4do/FprCfOebMoaT\n'
         'Ef6Rr3WDsNX8TDx3mx37+1sNyjFQ0F/YHS0gF0LF99VHzuSXMxB1UOLtUTNqhuEV\n'
         'IWY+XLFBH+tEaumNXKYQTzHhI7uukIfR285a5zv1eOBs6XsYInlkfd4VIx70CYcT\n'
         'zP56V6lQC7L5UbeYklwcaF0mZL++QBjyb1e14ucCAwEAATANBgkqhkiG9w0BAQsF\n'
         'AAOCAQEAtaOiX9ersbunQc5lQnDSQuQqmR7+CmCTpJFSTkc1PEu3r421AZtU0S0S\n'
         'EjoQEPmnkuL0yVWr473AjbcgPoWPl7hLXXu1iAW31me2JIZLsSBF3hOt6sZDsjyd\n'
         'O0ZfdfijchXC25RfNW+9igF2HPyq+UkZgZq5/MsbpZKmKpsTaPaxZRv7dSXzYinT\n'
         'J4i0wi+9f9E1ezPlPvbEgIWjk1nQqerhhaExteMVS/eXq5mjC4mr83B0HNJeH4mX\n'
         'ZWqFjr5AbflTnGv9oFayWZcEST+IlkjT0l7iRp9ptgBwHerfUZs2XT7foydeRWWF\n'
         '4bdb6WHxX+vwj0kL5m2f180CA8agew==\n'
         '-----END CERTIFICATE-----', 
# 'cert_chain': None,
 'kwargs': {}
}

# the flask app_context is required to allow logger works
app = Flask(__name__)
app.debug = True
with app.app_context():
    SFTPDestinationPlugin().upload(**args)
