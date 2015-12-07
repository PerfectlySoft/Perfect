# Makefile for Perfect Server

SWIFTC = swift
SWIFTC_FLAGS = -frontend -c -module-cache-path $(MODULE_CACHE_PATH) -emit-module -I ../PerfectLib/PerfectLib -I ../PerfectLib/linked/LibEvent -I ../PerfectLib/linked/OpenSSL -I ../PerfectLib/linked/ICU -I ../PerfectLib/linked/SQLite3 -I ../PerfectLib/linked/LinuxBridge
MODULE_CACHE_PATH = /tmp/modulecache
SHLIB_PATH = /swift/usr/lib/swift/linux/
LFLAGS = -L$(SHLIB_PATH) -lFoundation -lswiftCore -lswiftGlibc ../PerfectLib/PerfectLib/PerfectLib.so

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

