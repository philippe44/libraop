CFLAGS 		+= -Wno-multichar -fdata-sections -ffunction-sections 

ifeq ($(OS),Darwin)
LINKSTATIC	=
LDFLAGS 	+= -Wl,-dead_strip
else
LINKSTATIC 	= -static
LDFLAGS 	+= -Wl,--gc-sections
endif

TOOLS		= ./tools
VALGRIND	= ../valgrind
ALAC		= ../alac
SRC 		= ./src
CURVE25519	= ../curve25519/source

LIBRARY 	=
DEFINES 	= 

vpath %.c $(TOOLS):$(SRC):$(ALAC):$(CURVE25519)
vpath %.cpp $(TOOLS):$(SRC):$(ALAC):$(CURVE25519)

INCLUDE = -I. \
		  -I$(VALGRIND)/memcheck -I$(VALGRIND)/include \
		  -I$(TOOLS) -I$(ALAC) \
		  -I$(SRC) -I$(SRC)/inc \
		  -I$(CURVE25519) -I$(CURVE25519)/include

SOURCES = log_util.c raop_client.c rtsp_client.c \
		  aes.c aexcl_lib.c base64.c alac_wrapper.cpp aes_ctr.c \
		  ag_dec.c ag_enc.c ALACBitUtilities.c ALACEncoder.cpp dp_enc.c EndianPortable.c matrix_enc.c \
		  curve25519_dh.c curve25519_mehdi.c curve25519_order.c curve25519_utils.c custom_blind.c\
		  ed25519_sign.c ed25519_verify.c \
		  sslshim.c \
		  raop_play.c 
		
OBJECTS = $(patsubst %.c,$(OBJ)/%.o,$(filter %.c,$(SOURCES))) $(patsubst %.cpp,$(OBJ)/%.o,$(filter %.cpp,$(SOURCES)))

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LIBRARY) $(LDFLAGS) -o $@

$(OBJECTS): | bin $(OBJ)

$(OBJ):
	@mkdir -p $@
	
bin:	
	@mkdir -p bin

$(OBJ)/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@
	
$(OBJ)/%.o : %.cpp
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@
	
clean:
	rm -f $(OBJECTS) $(EXECUTABLE) 

