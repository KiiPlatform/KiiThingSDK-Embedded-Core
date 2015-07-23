override CFLAGS += -std=gnu89 -Wall -pedantic
ifdef DEBUG
CFLAGS += -g -DDEBUG
endif

LIBS = -lssl -lcrypto
SOURCES = $(wildcard *.c)
SOURCES += $(wildcard ../*.c)
TARGET = exampleapp

INCLUDE = ../kii_core.h

all: clean $(TARGET)

$(TARGET):
	gcc -include $(INCLUDE) $(CFLAGS) $(SOURCES) $(LIBS) -o $@

clean:
	touch $(TARGET)
	rm $(TARGET)

.PHONY: all clean
