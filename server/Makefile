MAKE= make
CC= gcc
CFLAGS= 
OBJ= main.o args.o common.o base_commands.o command.o core.o lock.o
#OBJ= main.o
TARGET= server
COMPILED= ./bin/
COMMON= ../common/
DEBUG= -ggdb

CFLAGS+= -D_DEBUG -D_C11 -D_BSD $(DEBUG)

all:	$(TARGET)
	@echo "Building pre-requirements"
#	@(mkdir @(COMPILED))
#	$(MAKE) -C $(COMMON)

$(TARGET):	main.o
	@echo "Building $(TARGET)"
	#$(CC) $(CFLAGS) -o $(COMPILED)/$(.ALLSRC)
	$(CC) $(CFLAGS) $(.ALLSRC) -lpthread -o $(TARGET)

$(OBJ):	$(.PREFIX).c
	$(CC) $(CFLAGS) -c $(.PREFIX).c

clean:
	@echo "Cleaning Stinger-Server build files..."
	rm *.o server 

