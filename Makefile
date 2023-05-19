all:
	cc -O2 -pipe -Wall -Wmissing-prototypes -Wmissing-declarations -Wshadow -Wpointer-arith -Wsign-compare -Werror-implicit-function-declaration -MD -MP -o rpkitouch rpkitouch.c -lc -lcrypto
	mandoc -Tlint rpkitouch.8

install:
	install -c -s -o root -g bin -m 555 rpkitouch /usr/local/bin/rpkitouch
	install -c -o root -g bin -m 444 rpkitouch.8 /usr/share/man/man8/rpkitouch.8

clean:
	-rm -f rpkitouch

readme:
	mandoc -T markdown rpkitouch.8 > README.md
