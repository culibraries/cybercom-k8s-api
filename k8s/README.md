# Cybercom Install

## Mongo

1. Set up Volume and set Cybercom Mongo User and Passwords from Secrets 

        $ rancher kubectl create -f cc-mongo-persistentvolumeclaim.yaml -n cybercom
        # The AWS Volume Persisten Volume clam needs to be setup
        $ rancher kubectl create  -f cybercom-mongo-job.yaml  -n cybercom

2. Deploy Mongo

        $ rancher kubectl create -f  cybercom-mongo-deployment.yaml -n cybercom

## RabbitMQ

1. Deploy

        $ rancher kubectl create -f  cybercom-rabbitmq-deployment.yaml -n cybercom

## Memcache

1. Deploy

        $ rancher kubectl create -f  cybercom-memcache-deployment.yaml -n cybercom

 


