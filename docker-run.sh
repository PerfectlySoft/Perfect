#!/bin/bash
arc=$(arch)
repo=rockywei/swift:5.6.$arc
solo=PerfectSMTPTests
docker run -it \
    -e LD_LIBRARY_PATH:/usr/lib/swift/linux \
    -p 8181:8181 \
    -v $PWD:/perfect \
    -w /perfect \
    $repo \
    /bin/bash -c "swift run"
