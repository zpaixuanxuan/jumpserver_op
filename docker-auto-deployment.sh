#!/usr/bin/env bash
set -e
#chmod +x /opt/zp/docker-tar
cd docker-tar
cat newjumpserver.tar | docker import - newjumpserver:0.1
cat newmysql.tar | docker import - newmysql:5.7
cat newnginx.tar | docker import - newnginx:latest
cd ../
docker-compose up -d
