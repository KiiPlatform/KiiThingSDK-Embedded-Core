build:
	gcc -shared kii.c 
	#gcc kii.c example.c -lssl -lcrypto

clean:
	rm a.out

.PHONY: build clean
