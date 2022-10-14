ifeq ($(CC),cc)
CC=$(lastword $(subst /, ,$(shell readlink -f `which cc`)))
endif

PLATFORM ?= $(firstword $(subst -, ,$(CC)))
HOST ?= $(word 2, $(subst -, ,$(CC)))

SRC 		= src
BIN		= bin/cliraop-$(PLATFORM)
LIB		= lib/$(HOST)/$(PLATFORM)/libraop.a
BUILDDIR	= build/$(PLATFORM)

DEFINES  = -DNDEBUG -D_GNU_SOURCE
CFLAGS  += -Wall -Wno-stringop-truncation -Wno-stringop-overflow -Wno-format-truncation -Wno-multichar -fPIC -ggdb -O2 $(DEFINES) -fdata-sections -ffunction-sections 
LDFLAGS += -s -lpthread -ldl -lm -lrt -lstdc++ -L. 

ifeq ($(OS),Darwin)
LDFLAGS 	+= -Wl,-dead_strip
else
LDFLAGS 	+= -Wl,--gc-sections
endif

TOOLS		= crosstools/src
#VALGRIND	= ../valgrind
DMAP_PARSER	= dmap-parser
MDNS		= libmdns/targets
CODECS		= libcodecs/targets
OPENSSL		= libopenssl/targets/$(HOST)/$(PLATFORM)

vpath %.c $(TOOLS):$(SRC):$(DMAP_PARSER)
vpath %.cpp $(TOOLS):$(SRC)

INCLUDE = -I$(VALGRIND)/memcheck -I$(VALGRIND)/include \
	  -I$(TOOLS) \
	  -I$(DMAP_PARSER) \
	  -I$(MDNS)/include/tinysvcmdns -I$(MDNS)/include/mdnssd \
	  -I$(OPENSSL)/include \
	  -I$(CODECS)/include/addons -I$(CODECS)/include/flac -I$(CODECS)/include/shine \
	  -I$(SRC) -I$(SRC)/inc
		  
CURVE25519_SOURCES = curve25519_dh.c curve25519_mehdi.c curve25519_order.c curve25519_utils.c custom_blind.c\
                     ed25519_sign.c ed25519_verify.c \		  

SOURCES = raop_client.c rtsp_client.c \
	  raop_server.c raop_streamer.c \
	  aes.c base64.c aes_ctr.c base64.c \
	  dmap_parser.c	\
	  alac.c 
		  
SOURCES_BIN = cross_log.c cross_ssl.c cross_util.c cross_net.c platform.c cliraop.c 		  
		  
OBJECTS = $(patsubst %.c,$(BUILDDIR)/%.o,$(filter %.c,$(SOURCES)))
OBJECTS += $(patsubst %.cpp,$(BUILDDIR)/%.o,$(filter %.cpp,$(SOURCES)))

LIBRARY	= $(CODECS)/$(HOST)/$(PLATFORM)/libcodecs.a

ifneq ($(STATIC),)
LIBRARY	+= $(OPENSSL)/libopenssl.a
DEFINES += -DLINKALL
endif

all: lib $(BIN)
lib: directory $(LIB)
directory:
	@mkdir -p bin
	@mkdir -p lib/$(HOST)/$(PLATFORM)	
	@mkdir -p $(BUILDDIR)

$(BIN): $(SOURCES_BIN:%.c=$(BUILDDIR)/%.o) $(LIB) 
	$(CC) $^ $(LIBRARY) $(LDFLAGS) -o $@
	
$(LIB): $(OBJECTS)
	$(AR) rcs $@ $^

$(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@
	
$(BUILDDIR)/%.o : %.cpp
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

cleanlib:
	rm -f $(BUILDDIR)/*.o $(LIB) 

clean: cleanlib
	rm -f $(BIN)	

