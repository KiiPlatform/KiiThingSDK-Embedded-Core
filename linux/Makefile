override CFLAGS += -std=gnu89 -Wall -pedantic
ifdef DEBUG
CFLAGS += -g -DDEBUG
endif

LIBS = -lssl -lcrypto
SOURCES = $(wildcard *.c)
SOURCES += $(wildcard ../*.c)
TARGET = exampleapp

INCLUDES = -I../

all: clean $(TARGET)

$(TARGET):
	gcc $(INCLUDES) $(CFLAGS) $(SOURCES) $(LIBS) -o $@

clean:
	touch $(TARGET)
	rm $(TARGET)

.PHONY: all clean
