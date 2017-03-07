#!/bin/bash
docker build . -t base_img
docker run -v $PWD/src:/tmp/src -i -t base_img bash