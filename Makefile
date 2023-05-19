all:
	cc -o rpkitouch rpkitouch.c -lc -lcrypto

clean:
	rm rpkitouch

readme:
	mandoc -T markdown rpkitouch.8 > README.md
