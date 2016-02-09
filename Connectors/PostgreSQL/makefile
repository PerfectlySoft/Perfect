# Makefile for Perfect Server

TARGET = PostgreSQL
OS = $(shell uname)
SWIFTC = swift
SWIFTC_FLAGS = -frontend -c -module-cache-path $(MODULE_CACHE_PATH) -emit-module -I /usr/local/lib -I ../../PerfectLib/linked/LibEvent \
	-I ../../PerfectLib/linked/OpenSSL_Linux -I ../../PerfectLib/linked/ICU -I ../../PerfectLib/linked/SQLite3 -I ../../PerfectLib/linked/LinuxBridge \
	-I ./linked/libpq -I ../../PerfectLib/linked/cURL_Linux
MODULE_CACHE_PATH = /tmp/modulecache
Linux_SHLIB_PATH = -L$(shell dirname $(shell dirname $(shell which swiftc)))/lib/swift/linux
SHLIB_PATH = $($(OS)_SHLIB_PATH)
LFLAGS = $(SHLIB_PATH) -luuid -lswiftCore -lswiftGlibc /usr/local/lib/PerfectLib.so -lpq -shared

all: $(TARGET)

modulecache:
	@mkdir -p $(MODULE_CACHE_PATH)

$(TARGET): $(TARGET).o
	clang++ $(LFLAGS) $< -o $@.so

$(TARGET).o: PostgreSQL.swift
	$(SWIFTC) $(SWIFTC_FLAGS) $< -o $@ -module-name $(TARGET) -emit-module-path $(TARGET).swiftmodule


clean:
	@rm *.o
