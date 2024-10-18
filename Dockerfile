FROM python:3.9-bookworm
SHELL ["/bin/bash", "-c"]
RUN apt-get update
RUN apt-get install -y make software-properties-common curl
RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get update
RUN apt-get install -y nodejs libldap2-dev=2.5.13+dfsg-5 libsasl2-dev libssl-dev
RUN python3 -m venv /opt/venv
RUN pip install pip==20.0.2
RUN pip install -U setuptools
RUN pip install coveralls bandit
WORKDIR /app
COPY . /app/
RUN pip install -e .
RUN pip install --no-cache-dir "file://`pwd`#egg=lemur[dev]"
RUN pip install --no-cache-dir "file://`pwd`#egg=lemur[tests]"

