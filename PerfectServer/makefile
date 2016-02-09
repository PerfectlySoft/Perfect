# Makefile for Perfect Server

TARGET_FCGI = perfectserverfcgi
TARGET_HTTP = perfectserverhttp
DEBUG = -g -Onone -Xcc -DDEBUG=1
OS = $(shell uname)
SWIFTC = swift
SWIFTC_FLAGS = -frontend $(DEBUG) -c -module-cache-path $(MODULE_CACHE_PATH) -emit-module -I /usr/local/lib -I ../PerfectLib/linked/LibEvent \
	-I ../PerfectLib/linked/OpenSSL -I ../PerfectLib/linked/ICU -I ../PerfectLib/linked/SQLite3 -I ../PerfectLib/linked/LinuxBridge -I ../PerfectLib/linked/cURL_Linux
MODULE_CACHE_PATH = /tmp/modulecache
Linux_SHLIB_PATH = $(shell dirname $(shell dirname $(shell which swiftc)))/lib/swift/linux
SHLIB_PATH = -L$($(OS)_SHLIB_PATH)
LFLAGS = $(SHLIB_PATH) -g -luuid -lcurl -lswiftCore -lswiftGlibc /usr/local/lib/PerfectLib.so -Xlinker -rpath -Xlinker $($(OS)_SHLIB_PATH)

all: modulecache $(TARGET_FCGI) $(TARGET_HTTP)


install: all
	ln -sf `pwd`/$(TARGET_FCGI) /usr/local/bin/
	ln -sf `pwd`/$(TARGET_HTTP) /usr/local/bin/

modulecache:
	@mkdir -p $(MODULE_CACHE_PATH)

$(TARGET_FCGI): $(TARGET_FCGI).o
	clang++ $(LFLAGS) $@.o -o $@

$(TARGET_HTTP): $(TARGET_HTTP).o
	clang++ $(LFLAGS) $@.o -o $@

$(TARGET_FCGI).o: main_fcgi.swift
	$(SWIFTC) $(SWIFTC_FLAGS) main.swift $< -o $@ -module-name $(subst .o,,$@) -emit-module-path $(subst .o,,$@).swiftmodule

$(TARGET_HTTP).o: main_http.swift
	$(SWIFTC) $(SWIFTC_FLAGS) main.swift $< -o $@ -module-name $(subst .o,,$@) -emit-module-path $(subst .o,,$@).swiftmodule

clean:
	@rm *.o
