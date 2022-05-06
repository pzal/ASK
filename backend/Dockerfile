FROM python:3.8-buster

# psql for wait-for-postgres script
RUN apt-get -y update
RUN apt-get install -y postgresql-client
RUN apt-get install -y wkhtmltopdf

ENV PYTHONUNBUFFERED 1

WORKDIR /code

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY requirements-dev.txt requirements-dev.txt

RUN pip install -r requirements-dev.txt
