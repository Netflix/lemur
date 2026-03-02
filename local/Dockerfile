FROM ubuntu:22.04

ARG VERSION
ARG URLCONTEXT

ENV uid 1337
ENV gid 1337
ENV user lemur
ENV group lemur
ENV DEBIAN_FRONTEND=noninteractive

# Create user and group
RUN groupadd -g ${gid} ${group} && \
    useradd -u ${uid} -g ${gid} -m -s /bin/bash ${user}

# Install Node.js 18 and all dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y --no-install-recommends \
    # Python runtime
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # Runtime dependencies
    libldap-2.5-0 \
    libsasl2-2 \
    postgresql-client \
    nginx \
    supervisor \
    tzdata \
    openssl \
    bash \
    cron \
    # Build dependencies
    build-essential \
    autoconf \
    automake \
    cargo \
    git \
    libffi-dev \
    libpq-dev \
    libldap2-dev \
    libsasl2-dev \
    libxml2-dev \
    libssl-dev \
    make \
    nasm \
    nodejs \
    tar && \
    rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /opt/lemur /opt/lemur/lemur /home/lemur/.lemur /run/nginx/ /etc/nginx/ssl/
COPY local/lemur-dev.tar.gz /opt/lemur

WORKDIR /opt/lemur
RUN tar -xvzf lemur-dev.tar.gz && \
    find . -name '._*' -type f -delete && \
    find . -name '.DS_Store' -type f -delete && \
    chown -R $user:$group /opt/lemur/ /home/lemur/.lemur/

COPY local/entrypoint /
COPY local/supervisor.conf /
COPY local/nginx/nginx.conf /etc/nginx/
COPY local/nginx/default.conf /etc/nginx/conf.d/
COPY local/nginx/default-ssl.conf /etc/nginx/conf.d/

# Upgrade pip and display versions
RUN echo "Running with python:" && python3 -c 'import platform; print(platform.python_version())' && \
    echo "Running with nodejs:" && node -v && \
    pip3 install --no-cache-dir --upgrade pip setuptools wheel
RUN npm install --unsafe-perm
RUN pip3 install --no-cache-dir -e .
RUN node_modules/.bin/gulp build
RUN node_modules/.bin/gulp package --urlContextPath=${URLCONTEXT}

# Clean up build dependencies to reduce image size
RUN apt-get purge -y --auto-remove \
    build-essential \
    autoconf \
    automake \
    cargo \
    git \
    libffi-dev \
    libpq-dev \
    libldap2-dev \
    libsasl2-dev \
    libxml2-dev \
    libssl-dev \
    make \
    nasm && \
    rm -rf /var/lib/apt/lists/*

# Install development and test dependencies
RUN pip install --no-cache-dir -e ."[dev]" -e ."[tests]"

COPY local/src/lemur.conf.py /home/lemur/.lemur/lemur.conf.py
COPY local/create_defaults.py /home/lemur/.lemur/create_defaults.py
COPY local/testing/ /opt/lemur/local/testing/

# Fix ownership and permissions
RUN chown -R $user:$group /opt/lemur/ /home/lemur/.lemur/ && \
    chmod +x /entrypoint

# Set LEMUR_CONF as a persistent environment variable
ENV LEMUR_CONF=/home/lemur/.lemur/lemur.conf.py
WORKDIR /

HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \
CMD curl --fail http://localhost:80/api/1/healthcheck | grep -q ok || exit 1
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj "/C=US/ST=NY/L=New York/O=Eng/CN=www.example.com"

# Use this to stop the container in case of a crash loop and use
# "docker exec -it local-lemur bash" to troubleshoot.
# CMD ["tail", "-f", "/dev/null"]

ENTRYPOINT ["/entrypoint"]

CMD ["/usr/bin/supervisord","-c","supervisor.conf"]
