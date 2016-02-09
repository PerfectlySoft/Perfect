# Makefile for Perfect Server

TARGET = MongoDB
OS = $(shell uname)
SWIFTC = swift
SWIFTC_FLAGS = -frontend -c -module-cache-path $(MODULE_CACHE_PATH) -emit-module -I /usr/local/lib -I ../../PerfectLib/linked/LibEvent \
	-I ../../PerfectLib/linked/OpenSSL_Linux -I ../../PerfectLib/linked/ICU -I ../../PerfectLib/linked/SQLite3 -I ../../PerfectLib/linked/LinuxBridge -I ../../PerfectLib/linked/cURL_Linux \
	-I ./linked/libmongoc_linux -I /usr/local/include -Xcc -I/usr/local/include/libbson-1.0
MODULE_CACHE_PATH = /tmp/modulecache
Linux_SHLIB_PATH = -L$(shell dirname $(shell dirname $(shell which swiftc)))/lib/swift/linux
SHLIB_PATH = $($(OS)_SHLIB_PATH)
LFLAGS = $(SHLIB_PATH) -luuid -lswiftCore -lswiftGlibc /usr/local/lib/PerfectLib.so -lmongoc-1.0 -lbson-1.0 -L/usr/local/lib -shared

all: $(TARGET)

modulecache:
	@mkdir -p $(MODULE_CACHE_PATH)

$(TARGET): $(TARGET).o
	clang++ $(LFLAGS) $< -o $@.so

$(TARGET).o: BSON.swift MongoClient.swift MongoCollection.swift MongoCursor.swift MongoDatabase.swift
	$(SWIFTC) $(SWIFTC_FLAGS) $^ -o $@ -module-name $(TARGET) -emit-module-path $(TARGET).swiftmodule


clean:
	@rm *.o
