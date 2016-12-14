CC= gcc
CFLAGS= 
OBJS= common.o args.o core.o lock.o command.o base_commands.o
COMPILED= ./bin/

all:	$(OBJ)
	@echo "Compiling Common\n"

$(OBJ):	$(.PREFIX).c
	(CC) $(CFLAGS) -c $(.PREFIX).c

clean:
	@echo "Cleaning Stinger common objects files...\n"
	@(rm -rf ./bin)

