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

cc3200:
	cp -f kii.h CC3200/ && cp -f kii.c CC3200/ && cp -f kii_libc_wrapper.h CC3200/ && cp -f kii_libc_wrapper.c CC3200/

.PHONY: build clean cc3200 doc

