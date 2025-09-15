PROG=	rpkitouch
SRCS=	main.c parser.c ccr.c mkdir.c mktemp.c util.c
MAN=	rpkitouch.8

LDADD+= -lc -lcrypto

CFLAGS+= -O2 -pipe
CFLAGS+= -Wall
CFLAGS+= -Wmissing-prototypes -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wsign-compare -Wpointer-sign
CFLAGS+= -Werror-implicit-function-declaration
CFLAGS+= -MD -MP
CFLAGS+= -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE

$(PROG): $(SRCS) extern.h
	cc -o $(PROG) $(CFLAGS) $(SRCS) $(LDADD)

tags:
	ctags $(SRCS)

all: $(PROG) tags
	mandoc -Tlint $(MAN)

install:
	install -c -s -o root -g bin -m 555 rpkitouch /usr/local/bin/
	install -c -o root -g bin -m 444 rpkitouch.8 /usr/local/man/man8/

TEST_FILES = 40SlM-M4frFfmZ2HaMH0tlCageA.gbr FjSf5hX1GmGhKMu9AG7WVIl8m1M.asa
TEST_FILES += t7xg6ZtXdcYhy-YGTMk_ONTD31E.cer yqgF26w2R0m5sRVZCrbvD5cM29g.mft
TEST_FILES += 5EjPZ8Kw2_h5hRqKpwmjdnq7Tq8.roa yqgF26w2R0m5sRVZCrbvD5cM29g.crl
TEST_FILES += 9X0AhXWTJDl8lJhfOwvnac-42CA.spl

test: $(PROG)
	cd tests && touch $(TEST_FILES)
	cd tests && ../rpkitouch -v $(TEST_FILES)
	cd tests && ls -rl $(TEST_FILES) | awk '{ print $$5, $$6, $$7, $$8, $$9 }' | sort | tee outcome.txt
	mkdir -p tests/c
	cd tests && find $(TEST_FILES) | xargs ../rpkitouch -v -d ./c
	find tests/c -type f | sort | tee -a tests/outcome.txt
	diff tests/outcome.txt tests/expected_outcome.txt
	./rpkitouch -c tests/test.ccr | tee tests/outcome-ccr.txt
	diff tests/outcome-ccr.txt tests/expected_outcome-ccr.txt
	./rpkitouch -p tests/*.mft | tee tests/outcome-print-mft.txt
	diff tests/outcome-print-mft.txt tests/expected_outcome-print-mft.txt
	echo OK

clean:
	-rm -rf rpkitouch rpkitouch.d tests/outcome.txt tests/c tags
	-rm -rf tests/outcome-ccr.txt tests/outcome-print-mft.txt

readme:
	mandoc -T markdown rpkitouch.8 > README.md
