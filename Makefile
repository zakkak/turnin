CC= gcc
CFLAGS= -O2 -Wall -Werror

turnin4: turnin.o
	$(CC) $(CFLAGS) turnin.o -o turnin

install: turnin
	rm -f $(DESTDIR)/usr/bin/turnin
	cp -p turnin $(DESTDIR)/usr/bin/
	chmod u+s $(DESTDIR)/usr/bin/turnin
	cp -pf turnin.1 $(DESTDIR)/usr/share/man/man1/

clean:
	rm -f turnin turnin.o
