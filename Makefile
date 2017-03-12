TOOLS		= ./tools
VALGRIND	= ../valgrind
ALAC		= ../alac
SRC 		= ./src
LIBRARY 	=
DEFINES 	= 

vpath %.c $(TOOLS):$(SRC):$(ALAC)
vpath %.cpp $(TOOLS):$(SRC):$(ALAC)

INCLUDE = -I. \
		  -I$(VALGRIND)/memcheck -I$(VALGRIND)/include \
		  -I$(TOOLS) -I$(ALAC) \
		  -I$(SRC) -I$(SRC)/inc

SOURCES = log_util.c raop_client.c rtsp_client.c \
		  aes.c aexcl_lib.c base64.c alac_wrapper.cpp \
		  ag_dec.c ag_enc.c ALACBitUtilities.c ALACEncoder.cpp dp_enc.c EndianPortable.c matrix_enc.c \
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

