all:
	cc -O2 -pipe -Wall -Wmissing-prototypes -Wmissing-declarations -Wshadow -Wpointer-arith -Wsign-compare -Werror-implicit-function-declaration -MD -MP -o rpkitouch rpkitouch.c -lc -lcrypto
	mandoc -Tlint rpkitouch.8

install:
	install -c -s -o root -g bin -m 555 rpkitouch /usr/local/bin/rpkitouch
	install -c -o root -g bin -m 444 rpkitouch.8 /usr/share/man/man8/rpkitouch.8

test:
	touch tests/*.{roa,cer,crl,gbr,asa,mft}
	./rpkitouch tests/*.{roa,cer,crl,gbr,asa,mft}
	cd tests && ls -rl *.roa *.cer *.gbr *.asa *.crl *.mft | awk '{ print $$5, $$6, $$7, $$8, $$9 }' | sort > outcome.txt
	diff tests/outcome.txt tests/expected_outcome.txt

clean:
	-rm -f rpkitouch rpkitouch.d tests/outcome.txt

readme:
	mandoc -T markdown rpkitouch.8 > README.md
