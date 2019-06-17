CU Libraries K8s Cybercommons 
=======

The Cybercommons framework is a Django Rest Framework API. The API leverages MongoDB to provide a Catalog and Data Store for storing metadata and data within a JSON document database. The API also includes Celery which is an asynchronous task queue/job queue based on distributed message passing.

DEVELOPMENTAL AT THIS POINT! This is not an offical release. Please experiment and provide Github Issues or a  Pull Request with added enhancements. 


## Requirements

* Docker
* Docker Compose
    * `pip install docker-compose`

## Installation

1. Initialize

        $ git clone <git repo url>
        $ cd cybercommons/dc_config
        $ ./initializeCybercomDB
        $ cd ..

2. Edit values within dc_config/cybercom_config.env
3. Build and Deploy

        $ docker-compose build
        $ docker-compose up -d 

4. API running http://localhost:8080
    * Username: admin
    * Password: admincybercom

5. Kill

        $ docker-compose down

## TODO

1. SSL Creation - current config with preset SSL
2. NGINX config 
2. JWT PAY-LOAD
3. Integration with Kubernetes
