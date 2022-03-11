#!/bin/bash

cd ../../
docker run --rm -it -w /opt \
    -v $PWD/bruteloops/:/opt/bruteloops \
    -v $PWD/bruteloops/docker/entrypoint.sh:/sbin/run_tests \
    python:3.9 run_tests
