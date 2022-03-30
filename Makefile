###############################################################################
#
# Copyright 1993      Paul Eggert
# Copyright 2014      Foivos S. Zakkak <foivos@zakkak.net> and
#                     Antonios A. Chariton <daknob.mac@gmail.com>
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

CC      := gcc
CFLAGS  := -Wall -pthread -I./src
LDFLAGS := -lcrypto
EUID    := $(shell id -u -r)
DESTDIR ?=/usr
SOURCES := $(wildcard src/*.c)
SOURCES += obj/version.c            # This is automatically generated
HEADERS := $(wildcard src/*.h)
OBJECTS := ${SOURCES:src/%=obj/%}
OBJECTS := ${OBJECTS:%.c=%.o}
GIT:=$(shell which git)

.PHONY: check install uninstall clean

all: check turnin

# Check for root
check:
ifneq ($(EUID),0)
	@echo "Please run as root user"
	@exit 1
endif

obj/version.c: src/version.sed.me
ifdef GIT
	@if [ -d .git ]; then\
	  echo ' SED version.sed.me';\
	  mkdir -p $(dir $@);\
	  sed -r 's/^(char \*turninversion = ").*(";)/\1'`git describe`'\2/' $< > $@;\
	else\
	  rm -f $@;\
	  mkdir -p $(dir $@);\
	  cp $< $@;\
	fi;
else
	@rm -f $@
	@mkdir -p $(dir $@)
	@cp $< $@
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

%.o: %.c $(HEADERS)
	@mkdir -p $(dir $@)
	@echo ' CC ' $@
	@$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: src/%.c dep/%.d $(HEADERS)
	@mkdir -p $(dir $@)
	@echo ' CC ' $@
	@$(CC) $(CFLAGS) -c $< -o $@

turnin: check $(OBJECTS)
	@echo ' LD ' $@
	@$(CC) $(CFLAGS) $(OBJECTS) -o turnin $(LDFLAGS)

install: check turnin uninstall $(DESTDIR)/bin/verify-turnin
	@echo ' INST'
	mkdir -p $(DESTDIR)/bin/
	cp -p turnin $(DESTDIR)/bin/
	chmod ug+s $(DESTDIR)/bin/turnin
	mkdir -p $(DESTDIR)/share/man/man1/
	cp -p man/turnin.1 $(DESTDIR)/share/man/man1/
	chmod 755 $(DESTDIR)/bin/verify-turnin

$(DESTDIR)/bin/verify-turnin: scripts/verify-turnin.sed.me
ifdef GIT
	@if [ -d .git ]; then\
		echo ' SED verify-turnin.sed.me';\
		mkdir -p $(dir $@);\
		sed -r 's/^(VER = ").*(")/\1'`git describe`'\2/' $< > $@;\
		else\
		rm -rf $@;\
		mkdir -p $(dir $a);\
		cp $< $@;\
		fi;
else
	@rm -rf $@
	@mkdir -p $(dir $@)
	@cp $< $@
endif

uninstall: check
	-rm -f \
		$(DESTDIR)/bin/turnin \
		$(DESTDIR)/bin/verify-turnin \
		$(DESTDIR)/share/man/man1/turnin.1

clean:
	@echo ' CLN'
	rm -rf obj dep

distclean: clean
	@echo ' CLN dist'
	rm -f turnin
