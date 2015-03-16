CFLAGS = -std=gnu89
ifdef DEBUG
CFLAGS += -g -DDEBUG
endif

LIBS = -lssl -lcrypto
SOURCES = $(wildcard *.c)
TARGET = exampleapp

$(TARGET):
	gcc $(CFLAGS) $(SOURCES) $(LIBS) -o $@

clean:
	rm $(TARGET)

all: $(TARGET)

.PHONY: clean
