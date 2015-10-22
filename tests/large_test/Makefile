override CFLAGS += -std=gnu89 -Wall -pedantic -pthread
CXXFLAGS = -Wall -pedantic
#CFLAGS = -std=gnu89 -w -pedantic
ifdef DEBUG
CFLAGS += -g -DDEBUG
CXXFLAGS += -g -DDEBUG
endif

GTEST_PATH=../../gtest-1.7.0

KIISDKPARAM =
ifdef DEBUG
KIISDKPARAM += DEBUG=1
endif

LIBS = -lssl -lcrypto -lpthread -lkiie
LD_FLAGS = -L.
CC_OBJ = $(patsubst %.cc,%.o,$(wildcard *.cc)) ../../linux/kii_core_secure_socket.c ../../linux/kii_core_init.c
TARGET = testapp
INCLUDES = -I../../ -I../../linux -I$(GTEST_PATH)/include

KIISDKNAME = libkiie.so
KIISDK = ../../$(KIISDKNAME)

TEST = test

LIBGTEST=libgtest.a

all: clean $(TARGET)

$(LIBGTEST):
	g++ -isystem $(GTEST_PATH)/include -I$(GTEST_PATH) -pthread -c $(GTEST_PATH)/src/gtest-all.cc
	g++ -isystem $(GTEST_PATH)/include -I$(GTEST_PATH) -pthread -c $(GTEST_PATH)/src/gtest_main.cc
	ar -rv $(LIBGTEST) gtest-all.o gtest_main.o

$(KIISDK):
	$(MAKE) -C ../../ $(KIISDKPARAM) "CFLAGS+=-DKII_JSON_FIXED_TOKEN_NUM=256"
	cp $(KIISDK) ./

$(TARGET): $(KIISDK) $(LIBGTEST) $(CC_OBJ)
	g++ -o $(TARGET) $(CC_OBJ) $(INCLUDES) $(LD_FLAGS) $(LIBS) $(LIBGTEST)

.c.o:
	gcc $(CFLAGS) $(INCLUDES) -c $<

.cc.o:
	g++ $(CXXFLAGS) $(INCLUDES) -c $<

clean:
	touch $(TARGET)
	rm $(TARGET)
	rm -f *.o
	rm -f $(KIISDK)
	rm -f $(KIISDKNAME)
	rm -f $(LIBGTEST)

.PHONY: all clean copy

