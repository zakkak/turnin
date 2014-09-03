###############################################################################
#
#Copyright 1993      Paul Eggert
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
