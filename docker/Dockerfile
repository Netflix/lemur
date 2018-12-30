FROM alpine:3.8 as builder

ENV VERSION master
#ENV VERSION 0.7.0

ENV uid 1337
ENV gid 1337
ENV user lemur
ENV group lemur

#RUN adduser -D -S -u ${uid} ${user} -G ${group}

RUN addgroup -S ${group} -g ${gid} && adduser -D -S ${user} -G ${group} -u ${uid}

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

RUN npm install --unsafe-perm

RUN pip3 install --upgrade pip

RUN pip3 install setuptools
RUN pip3 install -e .

#RUN node_modules/.bin/gulp build --urlContextPath=/arnold/foo

RUN node_modules/.bin/gulp build

#RUN node_modules/.bin/gulp build -h

RUN node_modules/.bin/gulp package --urlContextPath=$(urlContextPath)

RUN apk del build-dependencies


#####################

RUN apk add --update libldap postgresql-client bash nginx supervisor curl

#RUN python3 /opt/lemur/lemur/manage.py reset_password -u lemur

RUN mkdir -p /run/nginx/

WORKDIR /

COPY entrypoint /

RUN chmod +x /entrypoint

#RUN mkdir -p /conf

COPY lemur.py /conf/lemur.conf.py

COPY supervisor.conf /
COPY default.conf /etc/nginx/conf.d/

HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \  
 CMD curl --fail http://localhost:80/api/1/healthcheck |grep -q ok || exit 1

ENTRYPOINT ["/entrypoint"]

#CMD ["python3","/lemur/lemur/manage.py","start","-b","0.0.0.0:8000"]

CMD ["/usr/bin/supervisord","-c","supervisor.conf"]
