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
GIT:=$(shell which git)

.PHONY: check install uninstall clean version

all: version check turnin

# Check for root
check:
ifneq ($(EUID),0)
	@echo "Please run as root user"
	@exit 1
endif

version:
ifdef GIT
	@if [ -d .git ]; then\
	  echo ' SED' $@;\
	  sed -ri 's/^(char \*turninversion = ").*(";)/\1'`git describe`'\2/' src/turnin.c;\
	fi;
endif

# Conditionally add dependencies rule
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
-include $(OBJECTS:obj/%.o=dep/%.d)
endif
endif

dep/%.d: src/%.c $(HEADERS)
	@mkdir -p $(dir $@)
	@echo ' DEP' $@
	@$(CC) $(CFLAGS) -M $< | \
		sed 's,[a-zA-Z0-9_\.]*.o:,$(<:src/%.c=obj/%.o):,' > $@

obj/%.o: src/%.c dep/%.d $(HEADERS)
	@mkdir -p $(dir $@)
	@echo ' CC ' $@
	@$(CC) $(CFLAGS) -c $< -o $@

turnin: check version $(OBJECTS)
	@echo ' LD ' $@
	@$(CC) $(CFLAGS) $(OBJECTS) -o turnin $(LDFLAGS)

install: check turnin uninstall
	@echo ' INST'
	cp -p turnin $(DESTDIR)/bin/
	chmod ug+s $(DESTDIR)/bin/turnin
	cp -p man/turnin.1 $(DESTDIR)/share/man/man1/

uninstall: check
	-rm -f \
		$(DESTDIR)/bin/turnin \
		$(DESTDIR)/share/man/man1/turnin.1

clean:
	@echo ' CLN'
	rm -rf obj dep

distclean: clean
	@echo ' CLN dist'
	rm -f turnin
