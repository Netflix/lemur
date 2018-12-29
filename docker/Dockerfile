FROM alpine:3.8 as builder

ARG VERSION

ENV VERSION master
#ENV VERSION 0.7.0

RUN apk --update add python3

RUN apk --update add --virtual build-dependencies \
                git \
                tar \
                curl \
                python3-dev \
                npm \
                bash \
                musl-dev \
                gcc \
                autoconf \
                automake \
                make \
                nasm  \
                zlib-dev \
                postgresql-dev \
                libressl-dev  \
                libffi-dev \
                cyrus-sasl-dev \
                openldap-dev

#RUN git clone https://github.com/Netflix/lemur

RUN mkdir -p /opt/lemur && curl -sSL https://github.com/Netflix/lemur/archive/$VERSION.tar.gz | tar xz -C /opt/lemur --strip-components=1

RUN ls -lha /opt/lemur/

WORKDIR /opt/lemur

RUN pip3 install --upgrade pip

RUN npm install --unsafe-perm
RUN pip3 install setuptools
RUN pip3 install -e .
RUN node_modules/.bin/gulp build
RUN node_modules/.bin/gulp package --urlContextPath=$(urlContextPath)

RUN apk del build-dependencies

#####################

RUN apk add --update libldap postgresql-client bash nginx supervisor

RUN mkdir -p /run/nginx/

WORKDIR /

COPY entrypoint /

RUN chmod +x /entrypoint

COPY lemur.py /root/.lemur/lemur.conf.py
COPY supervisor.conf /
COPY default.conf /etc/nginx/conf.d/

ENTRYPOINT ["/entrypoint"]

CMD ["/usr/bin/supervisord","-c","supervisor.conf"]
