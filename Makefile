CFLAGS = -std=gnu89 -Wall -pedantic
ifdef DEBUG
CFLAGS += -g -DDEBUG
endif

LIBS = -lssl -lcrypto
SOURCES = $(wildcard *.c)
TARGET = exampleapp

all: clean $(TARGET)

$(TARGET):
	gcc $(CFLAGS) $(SOURCES) $(LIBS) -o $@

clean:
	rm $(TARGET)

.PHONY: all clean
