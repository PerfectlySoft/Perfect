# Makefile for Perfect Server

OS = $(shell uname)
SWIFTC = swift
SWIFTC_FLAGS = -frontend -c -module-cache-path $(MODULE_CACHE_PATH) -emit-module -I /usr/local/lib -I ../PerfectLib/linked/LibEvent \
	-I ../PerfectLib/linked/OpenSSL -I ../PerfectLib/linked/ICU -I ../PerfectLib/linked/SQLite3 -I ../PerfectLib/linked/LinuxBridge
MODULE_CACHE_PATH = /tmp/modulecache
Linux_SHLIB_PATH = $(shell dirname $(shell dirname $(shell which swiftc)))/lib/swift/linux
SHLIB_PATH = -L$($(OS)_SHLIB_PATH)
LFLAGS = $(SHLIB_PATH) -lFoundation -lswiftCore -lswiftGlibc /usr/local/lib/PerfectLib.so -Xlinker -rpath -Xlinker $($(OS)_SHLIB_PATH)

all: perfectserverfcgi perfectserverhttp
	
modulecache:
	@mkdir -p $(MODULE_CACHE_PATH)

perfectserverfcgi: modulecache
	$(SWIFTC) $(SWIFTC_FLAGS) main.swift main_fcgi.swift -o $@.o -module-name $@ -emit-module-path $@.swiftmodule
	clang++ $(LFLAGS) $@.o -o $@

perfectserverhttp: modulecache
	$(SWIFTC) $(SWIFTC_FLAGS) main.swift main_http.swift -o $@.o -module-name $@ -emit-module-path $@.swiftmodule
	clang++ $(LFLAGS) $@.o -o $@

clean:
	@rm *.o

