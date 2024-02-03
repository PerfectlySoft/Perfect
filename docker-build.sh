#!/bin/bash
arc=$(arch)
repo=rockywei/swift:5.6.$arc
echo "building $repo"
docker build -t $repo --build-arg arch=$arc .
