# Cybercom Install

## Mongo

1. Set up Volume and set Cybercom Mongo User and Passwords from Secrets 

        $ rancher kubectl create -f cc-mongo-persistentvolumeclaim.yaml -n cybercom
        # The AWS Volume Persisten Volume clam needs to be setup
        $ rancher kubectl create  -f cybercom-mongo-job.yaml  -n cybercom
        

2. Deploy Mongo

        $ rk create -f cybercom-mongo-service.yaml -n cybercom
        $ rancher kubectl create -f  cybercom-mongo-deployment.yaml -n cybercom

## RabbitMQ

1. Deploy

        $ rancher kubectl create -f  cybercom-rabbitmq-deployment.yaml -n cybercom
        $ rk create -f cybercom-rabbitmq-service.yaml -n cybercom

## Memcache

1. Deploy

        $ rancher kubectl create -f  cybercom-memcache-deployment.yaml -n cybercom
        $ rk create -f cybercom-memcache-service.yaml -n cybercom


## Run ansible playbook for cybercom and geo


## Deploy api services

        $ rk create -f cybercom-api-service.yaml -n cybercom

 


