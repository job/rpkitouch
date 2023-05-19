all:
	cc -o rpkitouch rpkitouch.c -lc -lcrypto
	mandoc -Tlint rpkitouch.8

clean:
	-rm -f rpkitouch

readme:
	mandoc -T markdown rpkitouch.8 > README.md
