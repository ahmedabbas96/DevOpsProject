FROM python:3.7-slim-buster

# 👇 you can use env variables to pin library versions
ENV TINI_VERSION="v0.19.0"

# 👇
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

RUN pip install -U \
    pip \
    setuptools \
    wheel

WORKDIR /flaskapi

RUN useradd -m -r user && \
    chown user /flaskapi

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

USER user

ARG GIT_HASH
ENV GIT_HASH=${GIT_HASH:-dev}

ENTRYPOINT ["/tini", "--"]