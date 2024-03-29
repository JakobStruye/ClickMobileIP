# Warning: this file must be usable by regular make
# (unlike the Makefiles in subdirectories).

SHELL = /bin/sh


top_srcdir = ..
srcdir = .
top_builddir = ..
subdir = tools
conf_auxdir = $(top_srcdir)

prefix = /usr/local
bindir = /usr/local/bin
INSTALL = /usr/bin/install -c
mkinstalldirs = $(conf_auxdir)/mkinstalldirs

TOOLDIRS =  click-align click-check click-combine click-devirtualize click-fastclassifier click-flatten click-mkmindriver click-pretty click-undead click-xform click2xml click-install
TARGETS =  click-align click-check click-combine click-devirtualize click-fastclassifier click-flatten click-mkmindriver click-pretty click-undead click-xform click2xml
INSTALL_TARGETS =  install-click-align install-click-check install-click-combine install-click-devirtualize install-click-fastclassifier install-click-flatten install-click-mkmindriver install-click-pretty install-click-undead install-click-xform install-click2xml
CLEAN_TARGETS =  clean-click-align clean-click-check clean-click-combine clean-click-devirtualize clean-click-fastclassifier clean-click-flatten clean-click-mkmindriver clean-click-pretty clean-click-undead clean-click-xform clean-click2xml

all: $(TARGETS)

lib: always Makefile
	@cd lib && $(MAKE) all

click-align: lib Makefile
	@cd click-align && $(MAKE) all-local
install-click-align: lib Makefile
	@cd click-align && $(MAKE) install-local
clean-click-align:
	@cd click-align && $(MAKE) clean

click-check: lib Makefile
	@cd click-check && $(MAKE) all-local
install-click-check: lib Makefile
	@cd click-check && $(MAKE) install-local
clean-click-check:
	@cd click-check && $(MAKE) clean

click-combine: lib Makefile
	@cd click-combine && $(MAKE) all-local
install-click-combine: lib Makefile
	@cd click-combine && $(MAKE) install-local
clean-click-combine:
	@cd click-combine && $(MAKE) clean

click-devirtualize: lib Makefile
	@cd click-devirtualize && $(MAKE) all-local
install-click-devirtualize: lib Makefile
	@cd click-devirtualize && $(MAKE) install-local
clean-click-devirtualize:
	@cd click-devirtualize && $(MAKE) clean

click-fastclassifier: lib Makefile
	@cd click-fastclassifier && $(MAKE) all-local
install-click-fastclassifier: lib Makefile
	@cd click-fastclassifier && $(MAKE) install-local
clean-click-fastclassifier:
	@cd click-fastclassifier && $(MAKE) clean

click-flatten: lib Makefile
	@cd click-flatten && $(MAKE) all-local
install-click-flatten: lib Makefile
	@cd click-flatten && $(MAKE) install-local
clean-click-flatten:
	@cd click-flatten && $(MAKE) clean

click-install: lib Makefile
	@cd click-install && $(MAKE) all-local
install-click-install: lib Makefile
	@cd click-install && $(MAKE) install-local
clean-click-install:
	@cd click-install && $(MAKE) clean

click-ipopt: lib Makefile
	@cd click-ipopt && $(MAKE) all-local
install-click-ipopt: lib Makefile
	@cd click-ipopt && $(MAKE) install-local
clean-click-ipopt:
	@cd click-ipopt && $(MAKE) clean

click-mkmindriver: lib Makefile
	@cd click-mkmindriver && $(MAKE) all-local
install-click-mkmindriver: lib Makefile
	@cd click-mkmindriver && $(MAKE) install-local
clean-click-mkmindriver:
	@cd click-mkmindriver && $(MAKE) clean

click-pretty: lib Makefile
	@cd click-pretty && $(MAKE) all-local
install-click-pretty: lib Makefile
	@cd click-pretty && $(MAKE) install-local
clean-click-pretty:
	@cd click-pretty && $(MAKE) clean

click-undead: lib Makefile
	@cd click-undead && $(MAKE) all-local
install-click-undead: lib Makefile
	@cd click-undead && $(MAKE) install-local
clean-click-undead:
	@cd click-undead && $(MAKE) clean

click-xform: lib Makefile
	@cd click-xform && $(MAKE) all-local
install-click-xform: lib Makefile
	@cd click-xform && $(MAKE) install-local
clean-click-xform:
	@cd click-xform && $(MAKE) clean

click2xml: lib Makefile
	@cd click2xml && $(MAKE) all-local
install-click2xml: lib Makefile
	@cd click2xml && $(MAKE) install-local
clean-click2xml:
	@cd click2xml && $(MAKE) clean

udpgen: Makefile
	@cd udpgen && $(MAKE) all

always:
	@:

Makefile: $(srcdir)/Makefile.in
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

clean: $(CLEAN_TARGETS)
	@cd lib && $(MAKE) clean
distclean:
	@-for d in lib $(TOOLDIRS); do (cd $$d && $(MAKE) distclean); done
	-rm -f Makefile

install: install-subdirs
install-lib:
	@cd lib && $(MAKE) install-lib
install-subdirs: lib
	@for d in lib $(TARGETS); do (cd $$d && $(MAKE) install-local) || exit 1; done
install-include:
	@cd lib && $(MAKE) install-include
install-man:
	:
uninstall:
	@for d in lib $(TARGETS); do (cd $$d && $(MAKE) uninstall) || exit 1; done


.PHONY: all always lib \
	$(TOOLDIRS) \
	install install-include install-lib $(INSTALL_TARGETS) \
	clean distclean distdir $(CLEAN_TARGETS) \
	uninstall
