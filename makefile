CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=main.c syscall.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=odin
INSTPATH=/bin/odin

all: $(SOURCES) $(EXECUTABLE)
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@
.c.o:
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm -rf *o odin
install:
	cp -p ./odin $(INSTPATH);\
	chmod 700 $(INSTPATH);\
	echo "Installed" $(INSTPATH)
cleanall:
	rm -rf *o odin
	rm -rf $(INSTPATH)
