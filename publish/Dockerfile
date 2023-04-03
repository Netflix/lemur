# Lemur Builder
FROM registry.ddbuild.io/images/base/gbi-ubuntu_2004 as builder

ARG CI_COMMIT_SHA

USER root

COPY ./files/setup_14.x .
RUN chmod +x setup_14.x && \
    ./setup_14.x && \
    rm -rf setup_14.x && \
    apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev curl build-essential locales libffi-dev libsasl2-dev libldap2-dev \
        dh-autoreconf git python3-dev python3-pip python3-venv python3-wheel nodejs unzip make

# Download Lemur source code
RUN echo "Getting code from COMMIT SHA $CI_COMMIT_SHA"
RUN curl -OL "https://github.com/DataDog/lemur/archive/$CI_COMMIT_SHA.zip"
RUN mkdir -p /opt/lemur && \
    unzip $CI_COMMIT_SHA.zip && mv lemur-$CI_COMMIT_SHA/* /opt/lemur/

WORKDIR /opt/lemur

# Disable unused Lemur plugins
COPY ./files/disable_plugins.patch /opt/lemur
RUN patch -p0 -i disable_plugins.patch && rm -rf disable_plugins.patch

RUN npm config set registry http://registry.npmjs.org/ && \
    npm install npm -g && \
    echo "Running with nodejs:" && node -v && \
    python3 -m venv /opt/venv && \
    echo "Running with python:" && /opt/venv/bin/python3 -c 'import platform; print(platform.python_version())' && \
    /opt/venv/bin/python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    # ddtrace is required to automatically instrument lemur to emit traces
    /opt/venv/bin/python3 -m pip install --no-cache-dir ddtrace && \
    /opt/venv/bin/python3 -m pip install --no-cache-dir -e . && \
    # install the statsd plugin required to emit metrics to datadog
    /opt/venv/bin/python3 -m pip install --no-cache-dir -e /opt/lemur/lemur/plugins/lemur_statsd && \
    npm install --unsafe-perm && \
    node_modules/.bin/gulp --cwd /opt/lemur build && \
    node_modules/.bin/gulp --cwd /opt/lemur package && \
    npm cache clean --force && \
    rm -rf node_modules

# Lemur Application
FROM registry.ddbuild.io/images/base/gbi-ubuntu_2004

USER root

RUN apt-get update && apt-get -y install jq

COPY --from=builder /opt/lemur /opt/lemur
COPY --from=builder /opt/venv /opt/venv

RUN clean-apt install python3 python3-distutils haveged curl postgresql-client openssl &&\
    chown -R dog:dog /opt

USER dog
