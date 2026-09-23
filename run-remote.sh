#!/bin/bash

GOARCH=arm64 go build -v -o coraldpi-arm64 && rsync coraldpi-arm64 router:/root/coraldpi-arm64 --progress
