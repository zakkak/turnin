###############################################################################
#
# Copyright 1993      Paul Eggert
# Copyright 2014      Foivos S. Zakkak <foivos@zakkak.net>
# Copyright 2014      Antonios A. Chariton <daknob@tolabaki.gr>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

CC= gcc
CFLAGS= -Wall -Werror
LDFLAGS= -lcrypto

turnin: turnin.o
	$(CC) $(CFLAGS) turnin.o -o turnin $(LDFLAGS)

install: turnin uninstall
	cp -p turnin $(DESTDIR)/usr/bin/
	chmod ug+s $(DESTDIR)/usr/bin/turnin
	cp -pf turnin.1 $(DESTDIR)/usr/share/man/man1/

uninstall:
	-rm -f $(DESTDIR)/usr/bin/turnin $(DESTDIR)/usr/share/man/man1/turnin.1

clean:
	rm -f turnin turnin.o
