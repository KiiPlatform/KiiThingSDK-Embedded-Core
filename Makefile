build:
	gcc -w kii.c example.c -lssl -lcrypto -DDEBUG
	#gcc kii.c example.c -lssl -lcrypto

clean:
	rm a.out

.PHONY: build clean
