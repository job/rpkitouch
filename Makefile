all:
	cc -o rpkitouch rpkitouch.c -lc -lcrypto

clean:
	rm rpkitouch
