Production
**********

There are several steps needed to make Lemur production ready. Here we focus on making Lemur more reliable and secure.

Basics
======

Because of the sensitivity of the information stored and maintain by Lemur it is important that you follow standard host hardening practices:

- Run Lemur with a limited user
- Disabled any unneeded service
- Enable remote logging

.. _CredentialManagement:

Credential Management
---------------------

Lemur often contains credentials such as mutual SSL keys that are used to communicate with third party resources and for encrypting stored secrets. Lemur comes with the ability
to automatically encrypt these keys such that your keys not be in clear text.

The keys are located within lemur/keys and broken down by environment

To utilize this ability use the following commands:

    ``lemur lock``

and

    ``lemur unlock``

If you choose to use this feature ensure that the KEY are decrypted before Lemur starts as it will have trouble communicating with the database otherwise.

SSL
====

Nginx
-----

Nginx is a very popular choice to serve a Python project:

- It's fast.
- It's lightweight.
- Configuration files are simple.

Nginx doesn't run any Python process, it only serves requests from outside to
the Python server.

Therefor there are two steps:

- Run the Python process.
- Run Nginx.

You will benefit from having:

- the possibility to have several projects listening to the port 80;
- your web site processes won't run with admin rights, even if --user doesn't
  work on your OS;
- the ability to manage a Python process without touching Nginx or the other
  processes. It's very handy for updates.


You must create a Nginx configuration file for Lemur. On GNU/Linux, they usually
go into /etc/nginx/conf.d/. Name it lemur.conf.

The minimal configuration file to run the site is::

    server {
        listen       80;
        server_name www.yourwebsite.com;

        location / {
            proxy_pass http://127.0.0.1:5000;
        }
    }

`proxy_pass` just passes the external request to the Python process.
The port much match the one used by the 0bin process of course.

You can make some adjustments to get a better user experience::

    server_tokens off;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    server {
      listen       80;
      return       301 https://$host$request_uri;
    }

    server {
       listen      443;
       access_log  /var/log/nginx/log/lemur.access.log;
       error_log   /var/log/nginx/log/lemur.error.log;

       location /api {
            proxy_pass  http://127.0.0.1:5000;
            proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
            proxy_redirect off;
            proxy_buffering off;
            proxy_set_header        Host            $host;
            proxy_set_header        X-Real-IP       $remote_addr;
            proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location / {
            root /apps/lemur/lemur/static/dist;
            index index.html;
        }


    }

This makes Nginx serve the favicon and static files which is is much better at than python.

It is highly recommended that you deploy SSL when deploying Lemur. This may be obvious given Lemur's purpose but the
sensitive nature of Lemur and what it controls makes this essential. This is a sample config for Lemur that also terminates SSL::

    server_tokens off;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    server {
      listen       80;
      return       301 https://$host$request_uri;
    }

    server {
       listen      443;
       access_log  /var/log/nginx/log/lemur.access.log;
       error_log   /var/log/nginx/log/lemur.error.log;

       # certs sent to the client in SERVER HELLO are concatenated in ssl_certificate
       ssl_certificate /path/to/signed_cert_plus_intermediates;
       ssl_certificate_key /path/to/private_key;
       ssl_session_timeout 1d;
       ssl_session_cache shared:SSL:50m;

       # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
       ssl_dhparam /path/to/dhparam.pem;

       # modern configuration. tweak to your needs.
       ssl_protocols TLSv1.1 TLSv1.2;
       ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK';
       ssl_prefer_server_ciphers on;

       # HSTS (ngx_http_headers_module is required) (15768000 seconds = 6 months)
       add_header Strict-Transport-Security max-age=15768000;

       # OCSP Stapling ---
       # fetch OCSP records from URL in ssl_certificate and cache them
       ssl_stapling on;
       ssl_stapling_verify on;

       ## verify chain of trust of OCSP response using Root CA and Intermediate certs
       ssl_trusted_certificate /path/to/root_CA_cert_plus_intermediates;

       resolver <IP DNS resolver>;

       location /api {
            proxy_pass  http://127.0.0.1:5000;
            proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
            proxy_redirect off;
            proxy_buffering off;
            proxy_set_header        Host            $host;
            proxy_set_header        X-Real-IP       $remote_addr;
            proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location / {
            root /apps/lemur/lemur/static/dist;
            index index.html;
        }


    }

Apache
------

An example apache config::

    <VirtualHost *:443>
        ...
        SSLEngine on
        SSLCertificateFile      /path/to/signed_certificate
        SSLCertificateChainFile /path/to/intermediate_certificate
        SSLCertificateKeyFile   /path/to/private/key
        SSLCACertificateFile    /path/to/all_ca_certs

        # intermediate configuration, tweak to your needs
        SSLProtocol             all -SSLv2 -SSLv3
        SSLCipherSuite          ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
        SSLHonorCipherOrder     on

        # HSTS (mod_headers is required) (15768000 seconds = 6 months)
        Header always set Strict-Transport-Security "max-age=15768000"
        ...
    </VirtualHost>

Also included in the configurations above are several best practices when it comes to deploying SSL. Things like enabling
HSTS, disabling vulnerable ciphers are all good ideas when it comes to deploying Lemur into a production environment.

.. seealso::
    `Mozilla SSL Configuration Generator <https://mozilla.github.io/server-side-tls/ssl-config-generator/>`_

.. _UsingSupervisor:

Supervisor
==========

Supervisor is a very nice way to manage you Python processes. We won't cover
the setup (which is just apt-get install supervisor or pip install supervisor
most of the time), but here is a quick overview on how to use it.

Create a configuration file named supervisor.ini::

    [unix_http_server]
    file=/tmp/supervisor.sock;

    [supervisorctl]
    serverurl=unix:///tmp/supervisor.sock;

    [rpcinterface:supervisor]
    supervisor.rpcinterface_factory=supervisor.rpcinterface:make_main_rpcinterface

    [supervisord]
    logfile=/tmp/lemur.log
    logfile_maxbytes=50MB
    logfile_backups=2
    loglevel=trace
    pidfile=/tmp/supervisord.pid
    nodaemon=false
    minfds=1024
    minprocs=200
    user=lemur

    [program:lemur]
    command=python /path/to/lemur/manage.py manage.py start

    directory=/path/to/lemur/
    environment=PYTHONPATH='/path/to/lemur/'
    user=lemur
    autostart=true
    autorestart=true

The 4 first entries are just boiler plate to get you started, you can copy
them verbatim.

The last one define one (you can have many) process supervisor should manage.

It means it will run the command::

    python manage.py start


In the directory, with the environment and the user you defined.

This command will be ran as a daemon, in the background.

`autostart` and `autorestart` just make it fire and forget: the site will always be
running, even it crashes temporarily or if you restart the machine.

The first time you run supervisor, pass it the configuration file::

    supervisord -c /path/to/supervisor.ini

Then you can manage the process by running::

    supervisorctl -c /path/to/supervisor.ini

It will start a shell from were you can start/stop/restart the service

You can read all errors that might occurs from /tmp/lemur.log.
