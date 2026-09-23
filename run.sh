#!/bin/bash

go build -v && sudo setcap 'cap_net_raw=ep' ./coraldpi && ./coraldpi
