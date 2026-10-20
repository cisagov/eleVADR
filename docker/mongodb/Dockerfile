# eleVADR MongoDB image used for development and deployed environments.
# The base image creates the root user from MONGODB_INITDB_ROOT_USERNAME and
# MONGODB_INITDB_ROOT_PASSWORD when /data/db is empty.
FROM docker.io/mongodb/mongodb-community-server:8.0.32-ubi9-slim

COPY mongod.conf /etc/mongod.conf

EXPOSE 27017

CMD ["mongod", "--config", "/etc/mongod.conf"]
