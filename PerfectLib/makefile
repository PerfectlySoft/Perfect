# Makefile for server-side PerfectLib

OS = $(shell uname)
SWIFTC = swift
SWIFT_LIBS_LOC = $(shell dirname $(shell dirname $(shell which swiftc)))/lib/swift/linux
MODULE_NAME = PerfectLib

Darwin_SWIFTC_FLAGS = -sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk
Linux_SWIFTC_FLAGS = -I linked/LinuxBridge

SWIFTC_FLAGS = -emit-module -I linked/LibEvent -I linked/OpenSSL -I linked/ICU -I linked/SQLite3 \
	-module-cache-path $(MODULE_CACHE_PATH) -module-name $(MODULE_NAME) $($(OS)_SWIFTC_FLAGS)

PERFECT_SRC = ICU.swift NetNamedPipe.swift File.swift Threading.swift LibEvent.swift Bytes.swift FastCGI.swift \
	LogManager.swift NetTCPSSL.swift PerfectServer.swift WebConnection.swift Closeable.swift \
	FastCGIServer.swift Net.swift Utilities.swift MimeReader.swift NetTCP.swift SessionManager.swift \
	WebRequest.swift HTTPServer.swift MimeType.swift PageHandler.swift SQLite.swift WebResponse.swift \
	Dir.swift Mustache.swift PerfectError.swift SysProcess.swift DynamicLoader.swift JSON.swift Utilities-Server.swift

PERFECT_OBJ = $(addsuffix .o, $(basename $(PERFECT_SRC))) LinuxBridge.o util.o

PERFECT_MODULES = $(addsuffix ~partial.swiftmodule, $(basename $(PERFECT_SRC)))

Darwin_SHLIB_PATH = -L./linked/ICU/osx -L./linked/LibEvent/osx -L./linked/OpenSSL/osx -L./linked/SQLite3/osx
Linux_SHLIB_PATH = -L$(SWIFT_LIBS_LOC)
SHLIB_PATH = $($(OS)_SHLIB_PATH)

Darwin_LFLAGS = $(SHLIB_PATH) -arch x86_64 -dynamiclib \
	-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk \
	-install_name @rpath/PerfectLib.framework/Versions/A/PerfectLib -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
	-Xlinker -rpath -Xlinker @loader_path/Frameworks -stdlib=libc++ \
	-L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx \
	-Xlinker -add_ast_path -Xlinker PerfectLib.swiftmodule -single_module

Linux_LFLAGS = $(SHLIB_PATH) -lFoundation -lswiftCore -lswiftGlibc -ldl -lm -shared

LFLAGS = $($(OS)_LFLAGS) -levent -levent_pthreads -lssl -lcrypto -lsqlite3 -licudata -licui18n -licuuc -lpthread
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
