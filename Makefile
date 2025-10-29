ifeq ($(CC),cc)
CC=$(lastword $(subst /, ,$(shell readlink -f `which cc`)))
endif

ifeq ($(findstring gcc,$(CC)),gcc)
CFLAGS  += -Wno-stringop-truncation -Wno-stringop-overflow -Wno-format-truncation -Wno-multichar
LDFLAGS += -s -lstdc++ -latomic
else
CFLAGS += -fno-temp-file
LDFLAGS += -lc++
endif

PLATFORM ?= $(firstword $(subst -, ,$(CC)))
HOST ?= $(word 2, $(subst -, ,$(CC)))

SRC        = src
CORE       = bin/cliraop-$(HOST)
BUILDDIR   = $(dir $(CORE))$(HOST)/$(PLATFORM)
LIB        = lib/$(HOST)/$(PLATFORM)/libraop.a
EXECUTABLE = $(CORE)-$(PLATFORM)

DEFINES  = -DNDEBUG -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED
CFLAGS  += -Wall -fPIC -ggdb -O2 $(DEFINES) -fdata-sections -ffunction-sections
LDFLAGS += -lpthread -ldl -lm -L.

TOOLS		= crosstools/src
FETCHER		= http-fetcher
DMAP_PARSER	= dmap-parser
MDNS		= libmdns/targets
CODECS		= libcodecs/targets
OPENSSL		= libopenssl/targets/$(HOST)/$(PLATFORM)

vpath %.c $(TOOLS):$(SRC):$(DMAP_PARSER):$(FETCHER)/src
vpath %.cpp $(TOOLS):$(SRC):$(FETCHER)/src

INCLUDE = -I$(VALGRIND)/memcheck -I$(VALGRIND)/include \
	-I$(TOOLS) \
	-I$(DMAP_PARSER) \
	-I$(MDNS)/include/mdnssvc -I$(MDNS)/include/mdnssd \
	-I$(OPENSSL)/include \
	-I$(CODECS)/include/addons -I$(CODECS)/include/flac \
	-I$(CODECS)/include/shine -I$(CODECS)/include/faac \
	-I$(SRC) -I$(SRC)/inc \
	-I$(FETCHER)/include \
	-Icrosstools/src

CURVE25519_SOURCES = curve25519_dh.c curve25519_mehdi.c curve25519_order.c curve25519_utils.c custom_blind.c\
                     ed25519_sign.c ed25519_verify.c \

SOURCES = raop_client.c rtsp_client.c \
	  raop_server.c raop_streamer.c \
	  aes.c aes_ctr.c \
	  dmap_parser.c	\
	  alac.c \
	  http_fetcher.c http_error_codes.c

SOURCES_BIN = cross_log.c cross_ssl.c cross_util.c cross_net.c platform.c cliraop.c pairing.cpp bplist.cpp
ifndef CXX
	CXX = g++
endif
CXXFLAGS ?= -Wall -O2 -std=c++17

OBJECTS = $(patsubst %.c,$(BUILDDIR)/%.o,$(filter %.c,$(SOURCES)))
OBJECTS += $(patsubst %.cpp,$(BUILDDIR)/%.o,$(filter %.cpp,$(SOURCES)))

OBJECTS_BIN = $(patsubst %.c,$(BUILDDIR)/%.o,$(filter %.c,$(SOURCES_BIN)))
OBJECTS_BIN += $(patsubst %.cpp,$(BUILDDIR)/%.o,$(filter %.cpp,$(SOURCES_BIN)))

LIBRARY	= $(CODECS)/$(HOST)/$(PLATFORM)/libcodecs.a $(MDNS)/$(HOST)/$(PLATFORM)/libmdns.a

ifneq ($(STATIC),)
LIBRARY	+= $(OPENSSL)/libopenssl.a
DEFINES += -DSSL_STATIC_LIB
endif

all: lib $(EXECUTABLE)
lib: directory $(LIB)
directory:
	@mkdir -p lib/$(HOST)/$(PLATFORM)
	@mkdir -p $(BUILDDIR)

$(EXECUTABLE): $(OBJECTS_BIN) $(LIB)
	$(CXX) $(OBJECTS_BIN) $(LIB) $(LIBRARY) $(LDFLAGS) -o $@
ifeq ($(HOST),macos)
	rm -f $(CORE)
	lipo -create -output $(CORE) $$(ls $(CORE)* | grep -v '\-static')
endif

$(LIB): $(OBJECTS)
	$(AR) rcs $@ $^

$(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(BUILDDIR)/%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

cleanlib:
	rm -f $(BUILDDIR)/*.o $(LIB)

clean: cleanlib
	rm -f $(EXECUTABLE)	$(CORE)

