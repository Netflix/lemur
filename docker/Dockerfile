FROM python:3.7.9-alpine3.12

ARG VERSION
ENV VERSION master

ARG URLCONTEXT

ENV uid 1337
ENV gid 1337
ENV user lemur
ENV group lemur

RUN addgroup -S ${group} -g ${gid} && \
    adduser -D -S ${user} -G ${group} -u ${uid} && \
    apk add --no-cache --update python3 py-pip libldap postgresql-client nginx supervisor curl tzdata openssl bash && \
    apk --update add --virtual build-dependencies \
                git \
                tar \
                curl \
                python3-dev \
                npm \
                bash \
                musl-dev \
                cargo \
                gcc \
                autoconf \
                automake \
                libtool \
                make \
                nasm  \
                zlib-dev \
                postgresql-dev \
                libressl-dev  \
                libffi-dev \
                cyrus-sasl-dev \
                openldap-dev && \
    mkdir -p /opt/lemur /home/lemur/.lemur/ && \
    curl -sSL https://github.com/Netflix/lemur/archive/$VERSION.tar.gz | tar xz -C /opt/lemur --strip-components=1 && \
    pip3 install --upgrade pip && \
    pip3 install --upgrade setuptools && \
    mkdir -p /run/nginx/ /etc/nginx/ssl/ && \
    chown -R $user:$group /opt/lemur/ /home/lemur/.lemur/

WORKDIR /opt/lemur

RUN echo "Running with python:" && python -c 'import platform; print(platform.python_version())' && \
    echo "Running with nodejs:" && node -v && \
    npm install --unsafe-perm && \
    pip3 install -e . && \
    node_modules/.bin/gulp build && \
    node_modules/.bin/gulp package --urlContextPath=${URLCONTEXT} && \
    apk del build-dependencies

COPY entrypoint /
COPY src/lemur.conf.py /home/lemur/.lemur/lemur.conf.py
COPY supervisor.conf /
COPY nginx/default.conf /etc/nginx/conf.d/
COPY nginx/default-ssl.conf /etc/nginx/conf.d/

RUN chmod +x /entrypoint
WORKDIR /

HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \
 CMD curl --fail http://localhost:80/api/1/healthcheck | grep -q ok || exit 1

USER root

ENTRYPOINT ["/entrypoint"]

CMD ["/usr/bin/supervisord","-c","supervisor.conf"]
