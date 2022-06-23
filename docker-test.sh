#!/bin/bash
arc=$(arch)
repo=rockywei/swift:5.6.$arc
solo=PerfectSMTPTests
docker run -it \
    -e LD_LIBRARY_PATH:/usr/lib/swift/linux \
    -v $PWD:/perfect \
    -w /perfect \
    $repo \
    /bin/bash -c "./test-linux.sh"
