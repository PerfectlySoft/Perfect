# Makefile for server-side PerfectLib

SWIFTC = swift
MODULE_NAME = PerfectLib
SWIFTC_FLAGS = -emit-module -I linked/LibEvent -I linked/OpenSSL -I linked/ICU -I linked/SQLite3 -I linked/LinuxBridge \
	-module-cache-path $(MODULE_CACHE_PATH) -module-name $(MODULE_NAME)

PERFECT_SRC = ICU.swift NetNamedPipe.swift File.swift Threading.swift LibEvent.swift Bytes.swift FastCGI.swift \
	LogManager.swift NetTCPSSL.swift PerfectServer.swift WebConnection.swift Closeable.swift \
	FastCGIServer.swift Net.swift Utilities.swift \
	MimeReader.swift NetTCP.swift SessionManager.swift WebRequest.swift HTTPServer.swift MimeType.swift \
	PageHandler.swift SQLite.swift WebResponse.swift Dir.swift Mustache.swift PerfectError.swift SysProcess.swift \
	DynamicLoader.swift JSON.swift Utilities-Server.swift

PERFECT_OBJ = $(addsuffix .o, $(basename $(PERFECT_SRC))) LinuxBridge.o util.o

PERFECT_MODULES = $(addsuffix ~partial.swiftmodule, $(basename $(PERFECT_SRC)))

SHLIB_PATH = /swift/usr/lib/swift/linux/
LFLAGS = -L$(SHLIB_PATH) -lFoundation -lswiftCore -lswiftGlibc -lpthread -ldl -lm \
	-lsqlite3 -lssl -lcrypto -levent -levent_pthreads -licudata -licui18n -licuuc -shared
CFLAGS = -fPIC
MODULE_CACHE_PATH = /tmp/modulecache

all: perfectlib
	
modulecache:
	@mkdir -p $(MODULE_CACHE_PATH)

perfectlib: modulecache $(PERFECT_MODULES) LinuxBridge.o util.o
	$(SWIFTC) -frontend $(SWIFTC_FLAGS) $(PERFECT_MODULES) -parse-as-library -emit-module-doc-path $(MODULE_NAME).swiftdoc -o $(MODULE_NAME).swiftmodule
	clang++ $(PERFECT_OBJ) $(LFLAGS) -o $(MODULE_NAME).so
	@rm -f *.o *~partial.* *.swiftdeps *.d

clean:
	@rm -f *.o *.swiftmodule *.swiftdoc *.d *.swiftdeps

%~partial.swiftmodule : %.swift
	$(SWIFTC) -frontend -c $(subst $<,,$(PERFECT_SRC)) -primary-file $< -emit-module-path $@ \
		-emit-module-doc-path $(subst .swiftmodule,.swiftdoc,$@) \
		-emit-dependencies-path $(subst .swift,.d,$<) \
		-emit-reference-dependencies-path $(subst .swift,.swiftdeps,$<) \
		$(SWIFTC_FLAGS) $(SWIFTC_FLAGS) \
		-o $(subst .swift,.o,$<)
