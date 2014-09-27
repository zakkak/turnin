###############################################################################
#
# Copyright 1993      Paul Eggert
# Copyright 2014      Foivos S. Zakkak <foivos@zakkak.net> and
#                     Antonios A. Chariton <daknob@tolabaki.gr>
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
EUID=$(shell id -u -r)
DESTDIR?=/usr
SOURCES = $(wildcard src/*.c)
HEADERS = $(wildcard src/*.h)
OBJECTS = ${SOURCES:src/%.c=obj/%.o}

.PHONY: check install uninstall clean

all: check turnin

# Check for root
check:
ifneq ($(EUID),0)
	@echo "Please run as root user"
	@exit 1
endif

# Conditionally add dependencies rule
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
-include $(OBJECTS:obj/%.o=dep/%.d)
endif
endif

dep/%.d: src/%.c $(HEADERS)
	@mkdir -p $(dir $@)
	@echo ' ' DEP $@
	@$(CC) $(CFLAGS) -M $< | \
		sed 's,[a-zA-Z0-9_\.]*.o:,$(<:src/%.c=obj/%.o):,' > $@

obj/%.o: src/%.c dep/%.d $(HEADERS)
	@mkdir -p $(dir $@)
	@echo ' ' CC $@
	@$(CC) $(CFLAGS) -c $< -o $@

turnin: check $(OBJECTS)
	@echo ' ' LD $@
	@$(CC) $(CFLAGS) $(OBJECTS) -o turnin $(LDFLAGS)

install: check turnin uninstall
	cp -p turnin $(DESTDIR)/bin/
	chmod ug+s $(DESTDIR)/bin/turnin
	cp -p scripts/turnin_extract $(DESTDIR)/bin/
	cp -p scripts/turnin_mossextract $(DESTDIR)/bin/
	cp -p man/turnin.1 $(DESTDIR)/share/man/man1/

uninstall: check
	-rm -f \
		$(DESTDIR)/bin/turnin \
		$(DESTDIR)/bin/turnin_extract \
		$(DESTDIR)/bin/turnin_mossextract \
		$(DESTDIR)/share/man/man1/turnin.1

clean:
	rm -rf obj dep

distclean: clean
	rm -f turnin
