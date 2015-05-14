CFLAGS = -std=gnu89 -Wall -pedantic -fPIC -shared
ifdef DEBUG
CFLAGS += -g -DDEBUG
endif

LIBS = -lssl -lcrypto
SOURCES = $(wildcard *.c)
TARGET = libkiie.so

LINUX_EX = linux/exampleapp

all: clean $(TARGET) $(LINUX_EX) doc

$(TARGET):
	gcc $(CFLAGS) $(SOURCES) $(LIBS) -o $@

$(LINUX_EX):
	$(MAKE) -C linux

clean:
	touch $(TARGET)
	rm $(TARGET)
	$(MAKE) -C linux clean

doc:
	doxygen

.PHONY: build clean doc

