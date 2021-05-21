FROM python:3.7
RUN apt-get update
RUN apt-get install -y make software-properties-common curl
RUN curl -sL https://deb.nodesource.com/setup_7.x | bash -
RUN apt-get update
RUN apt-get install -y npm libldap2-dev libsasl2-dev libldap2-dev libssl-dev
RUN pip install pip==20.0.2
RUN pip install -U setuptools
RUN pip install coveralls bandit
WORKDIR /app
COPY . /app/
RUN pip install -e .
RUN pip install --require-hashes -r requirements-dev.txt
RUN pip install --require-hashes -r requirements-tests.txt
