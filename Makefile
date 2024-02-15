all:
	cc -O2 -pipe -Wall -Wmissing-prototypes -Wmissing-declarations -Wshadow -Wpointer-arith -Wsign-compare -Werror-implicit-function-declaration -MD -MP -o rpkitouch rpkitouch.c -lc -lcrypto
	mandoc -Tlint rpkitouch.8

install:
	install -c -s -o root -g bin -m 555 rpkitouch /usr/local/bin/rpkitouch
	install -c -o root -g bin -m 444 rpkitouch.8 /usr/share/man/man8/rpkitouch.8

test:
	cd tests && touch 40SlM-M4frFfmZ2HaMH0tlCageA.gbr FjSf5hX1GmGhKMu9AG7WVIl8m1M.asa t7xg6ZtXdcYhy-YGTMk_ONTD31E.cer yqgF26w2R0m5sRVZCrbvD5cM29g.mft 5EjPZ8Kw2_h5hRqKpwmjdnq7Tq8.roa yqgF26w2R0m5sRVZCrbvD5cM29g.crl 9X0AhXWTJDl8lJhfOwvnac-42CA.spl
	./rpkitouch -v tests/40SlM-M4frFfmZ2HaMH0tlCageA.gbr tests/FjSf5hX1GmGhKMu9AG7WVIl8m1M.asa tests/t7xg6ZtXdcYhy-YGTMk_ONTD31E.cer tests/yqgF26w2R0m5sRVZCrbvD5cM29g.mft tests/5EjPZ8Kw2_h5hRqKpwmjdnq7Tq8.roa tests/yqgF26w2R0m5sRVZCrbvD5cM29g.crl tests/9X0AhXWTJDl8lJhfOwvnac-42CA.spl
	cd tests && ls -rl 40SlM-M4frFfmZ2HaMH0tlCageA.gbr FjSf5hX1GmGhKMu9AG7WVIl8m1M.asa t7xg6ZtXdcYhy-YGTMk_ONTD31E.cer yqgF26w2R0m5sRVZCrbvD5cM29g.mft 5EjPZ8Kw2_h5hRqKpwmjdnq7Tq8.roa yqgF26w2R0m5sRVZCrbvD5cM29g.crl 9X0AhXWTJDl8lJhfOwvnac-42CA.spl | awk '{ print $$5, $$6, $$7, $$8, $$9 }' | sort > outcome.txt
	diff tests/outcome.txt tests/expected_outcome.txt
	echo OK

clean:
	-rm -f rpkitouch rpkitouch.d tests/outcome.txt

readme:
	mandoc -T markdown rpkitouch.8 > README.md
