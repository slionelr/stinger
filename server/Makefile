CC= gcc
CFLAGS= 
OBJS= main.o
TARGET= server
COMPILED= ./bin/

COMMON= <../common/Makefile>
#include $(COMMON)

all:	$(TARGET)
	@echo "Building $(TARGET)\n"

$(TARGET):	$(OBJ)
	$(CC) $(CFLAGS) -o $(COMPILED)/$(TARGET) $(.ALLSRC)

$(OBJ):	$(.PREFIX).c
	$(CC) $(CFLAGS) -c $(.PREFIX).c

clean:
	@echo "Cleaning Stinger-Server build files...\n"
	@(rm -rf ./bin)

