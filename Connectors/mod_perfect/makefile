
SRCS = mod_perfect.cpp
TARGET = mod_perfect

# OS settings
OS := $(shell uname -s)
ifeq ($(OS),Darwin)
  .DEFAULT_GOAL := all-osx
  MACOSX_DEPLOYMENT_TARGET := 10.11
  
  osx_A2_MODROOT = /usr/local
  SDKROOT := $(shell xcodebuild -version -sdk macosx$(MACOSX_DEPLOYMENT_TARGET) Path)
  MACOSX_VERSION_MIN := -isysroot $(SDKROOT) -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
  OS_NAME := osx
  OS_RELEASE := 10.7
else ifeq ($(OS),Linux)
  OS_NAME := $(shell lsb_release -is | awk '{print tolower($$0)}')
  OS_RELEASE := $(shell lsb_release -rs | cut -d . -f 1)
endif

ifneq ($(wildcard /etc/redhat-release),)
  CENTOS56 := $(shell cat /etc/redhat-release | grep "release [56]")
  CENTOS7 := $(shell cat /etc/redhat-release | grep "release 7")
endif

# Paths
osx_A2_MODS := $(osx_A2_MODROOT)/libexec/apache2
centos_A2_MODS := /usr/lib64/httpd/modules
ubuntu_A2_MODS := /usr/lib/apache2/modules
BUILDROOT := ./

# Flags
Darwin_ARCH = -arch x86_64
Darwin_CPPFLAGS = $(MACOSX_VERSION_MIN) -iprefix $(SDKROOT)/usr/include/ -iwithprefix apache2 -iwithprefix apr-1 -DDARWIN
Darwin_LDFLAGS = -bundle -undefined dynamic_lookup
Darwin_LDLIBS = 

Linux_ARCH = -march=x86-64
Linux_CPPFLAGS = -I/usr/include/httpd -I/usr/include/apr-1 -I/usr/include/apache2 -I/usr/include/apr-1.0
Linux_CXXFLAGS = -fPIC
Linux_LDFLAGS = -shared
Linux_LDLIBS = 

CPPFLAGS = $($(OS)_CPPFLAGS)
CXXFLAGS = $($(OS)_CXXFLAGS) -Wall
LDFLAGS = $($(OS)_LDFLAGS)
LDLIBS = $($(OS)_LDLIBS)

# http://httpd.apache.org
centos_A2_INSTALL = yum list installed httpd-devel.x86_64 > /dev/null || sudo yum -y install httpd-devel.x86_64
ubuntu_A2_INSTALL = dpkg -s apache2-dev > /dev/null || sudo apt-get -y install apache2-dev

# Rules
$(TARGET).so: $(SRCS)
	@$($(OS_NAME)_A2_INSTALL)
ifeq ($(OS)$(osx_A2_VERS),Darwin) # skip this rule on OS X if a target Apache version isn't specified
	$(error Ask for $(TARGET)-2.2.so or $(TARGET)-2.4.so on OS X)
endif
ifneq ($(OS)$(SDKROOT),Darwin) # skip this rule on OS X if the SDK isn't found
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) $(LDFLAGS) $^ $(LDLIBS) -o $@
endif

$(TARGET)-%.so:
	$(MAKE) $(TARGET).so osx_A2_VERS=$*

all-osx: $(TARGET)-2.2.so $(TARGET)-2.4.so
	

clean:
	@rm -f *.o *.so
