FROM python:3.5
RUN apt-get update
RUN apt-get install -y make python-software-properties curl
RUN curl -sL https://deb.nodesource.com/setup_7.x | bash -
RUN apt-get update
RUN apt-get install -y nodejs libldap2-dev libsasl2-dev libldap2-dev libssl-dev
RUN pip install -U setuptools
RUN pip install codecov bandit
WORKDIR /app
COPY . /app/
RUN pip install -e .
RUN pip install "file://`pwd`#egg=lemur[dev]"
RUN pip install "file://`pwd`#egg=lemur[tests]"
