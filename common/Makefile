CC= gcc
CFLAGS= 
OBJ= common.o args.o core.o lock.o command.o base_commands.o
INC_LIBS= -lpthread
COMPILED= ./bin

CFLAGS+= -D_DEBUG

all:	$(OBJ)
	@echo "Compiling Common"
	@(mkdir @(COMPILED))

$(OBJ):	$(.PREFIX).c
	$(CC) $(CFLAGS) $(INC_LIBS) -c $(.PREFIX).c -o $(COMPILED)/$(.PREFIX).o

clean:
	@echo "Cleaning Stinger common objects files..."
	@(rm -rf ./bin)

