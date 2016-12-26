TOOLS		= ./tools
VALGRIND	= ../valgrind
SRC 		= ./src
LIBRARY 	=
DEFINES 	= 

vpath %.c $(TOOLS):$(SRC)

INCLUDE = -I. \
		  -I$(VALGRIND)/memcheck -I$(VALGRIND)/include \
		  -I$(TOOLS) \
		  -I$(SRC) -I$(SRC)/inc

SOURCES = log_util.c raop_client.c rtsp_client.c \
		  aes.c aexcl_lib.c base64.c alac_wrapper.c \
		  raop_play.c
		
OBJECTS = $(patsubst %.c,$(OBJ)/%.o,$(SOURCES)) 

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
	
clean:
	rm -f $(OBJECTS) $(EXECUTABLE) 

