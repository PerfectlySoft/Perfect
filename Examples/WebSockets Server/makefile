# Makefile for Perfect Server

TARGET = WebSocketsServer
OS = $(shell uname)
SRC = "WebSockets Server/PerfectHandlers.swift"
PERFECT_ROOT = ../../PerfectLib
SWIFTC = swift
SWIFTC_FLAGS = -frontend -c -module-cache-path $(MODULE_CACHE_PATH) -emit-module -I /usr/local/lib -I $(PERFECT_ROOT)/linked/LibEvent \
	-I $(PERFECT_ROOT)/linked/OpenSSL_Linux -I $(PERFECT_ROOT)/linked/ICU -I $(PERFECT_ROOT)/linked/SQLite3 -I $(PERFECT_ROOT)/linked/LinuxBridge -I $(PERFECT_ROOT)/linked/cURL_Linux
MODULE_CACHE_PATH = /tmp/modulecache
Linux_SHLIB_PATH = $(shell dirname $(shell dirname $(shell which swiftc)))/lib/swift/linux
SHLIB_PATH = -L$($(OS)_SHLIB_PATH)
LFLAGS = $(SHLIB_PATH) -luuid -lswiftCore -lswiftGlibc /usr/local/lib/PerfectLib.so -Xlinker -rpath -Xlinker $($(OS)_SHLIB_PATH) -shared

all: $(TARGET)

modulecache:
	@mkdir -p $(MODULE_CACHE_PATH)

$(TARGET): modulecache
	$(SWIFTC) $(SWIFTC_FLAGS) $(SRC) -o $@.o -module-name $@ -emit-module-path $@.swiftmodule
	clang++ $(LFLAGS) $@.o -o $@.so

clean:
	@rm *.o
