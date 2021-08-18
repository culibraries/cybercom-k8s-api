#FROM python:3.6-alpine3.9
FROM python:3.8-alpine

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUNBUFFERED=1

WORKDIR /
COPY requirements.txt ./
# mysql requirements
RUN apk add mariadb-dev \
    gcc \
    musl-dev \
    libxml2-dev \
    libxslt-dev \
    xmlsec-dev \
    git \
    tzdata
RUN cp /usr/share/zoneinfo/America/Denver /etc/localtime

# numpy and pandas build requirements 
RUN apk --no-cache add musl-dev linux-headers g++
RUN pip install --upgrade pip

# App requirements
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install python3-saml==1.11
RUN rm requirements.txt
RUN mkdir -p /data/file_upload
RUN chmod -R 777 /data/file_upload
COPY . /app
WORKDIR /app

#Setup API User
RUN addgroup api && adduser -DH -G api apiuser
RUN chown apiuser:api -R /app

EXPOSE 8080
CMD ["su", "-p", "apiuser", "-c", "gunicorn --config=gunicorn.py api.wsgi:application"]
