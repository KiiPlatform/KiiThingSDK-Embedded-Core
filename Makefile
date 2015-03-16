build:
	gcc -w -g kii.c example.c -lssl -lcrypto -DDEBUG
	#gcc kii.c example.c -lssl -lcrypto

clean:
	rm a.out

cc3200:
	cp -f kii.h CC3200/ && cp -f kii.c CC3200/

.PHONY: build clean cc3200
