FROM debian:bullseye-slim

RUN mkdir /app
WORKDIR /app

COPY app/ /app

RUN apt-get update -y && apt-get install -y python3 python3-pip

RUN pip3 install -r requirements.txt