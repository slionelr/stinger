MAKE= make
CC= gcc
CFLAGS= 
OBJ= main.o
TARGET= server
COMPILED= ./bin/
COMMON= ../common/

CFLAGS+= -D_DEBUG

all:	$(TARGET)
	@echo "Building pre-requirements\n"
	$(MAKE) -C $(COMMON)
	@(mkdir @(COMPILED))

$(TARGET):	$(OBJ)
	@echo "Building $(TARGET)\n"
	$(CC) $(CFLAGS) -o $(COMPILED)/$(TARGET) $(.ALLSRC)

$(OBJ):	$(.PREFIX).c
	$(CC) $(CFLAGS) -c $(.PREFIX).c

clean:
	@echo "Cleaning Stinger-Server build files...\n"
	@(rm -rf ./bin)

