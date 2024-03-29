SHELL = /bin/sh

top_srcdir = ..
srcdir = .
top_builddir = ..
subdir = doc
conf_auxdir = $(top_srcdir)

prefix = /usr/local
exec_prefix = ${prefix}
bindir = /usr/local/bin
mandir = ${datarootdir}/man
datarootdir = /usr/local/share
datadir = /usr/local/share
clickdatadir = $(datadir)/click

PERL = perl
INSTALL = /usr/bin/install -c
INSTALL_DATA = $(INSTALL) -m 644
POD2MAN = pod2man
CP_PRESERVE = /bin/cp -p
mkinstalldirs = $(conf_auxdir)/mkinstalldirs

ifeq ($(V),1)
x_verbose_cmd = $(1) $(3)
verbose_cmd = $(1) $(3)
else
x_verbose_cmd = $(if $(2),/bin/echo ' ' $(2) $(3) &&,) $(1) $(3)
verbose_cmd = @$(x_verbose_cmd)
endif

EXTRA_PROVIDES =

all: Makefile

Makefile: $(srcdir)/Makefile.in
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

install: Makefile install-man
	$(call verbose_cmd,$(mkinstalldirs) $(DESTDIR)$(bindir))
	$(call verbose_cmd,$(INSTALL) $(srcdir)/click-elem2man,INSTALL,$(DESTDIR)$(bindir)/click-elem2man)
install-man: testie.1 $(top_builddir)/elementmap.xml Makefile
	$(call verbose_cmd,$(mkinstalldirs) $(DESTDIR)$(mandir)/man1 $(DESTDIR)$(mandir)/man3 $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man7 $(DESTDIR)$(mandir)/man8 $(DESTDIR)$(mandir)/mann)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click.1 $(DESTDIR)$(mandir)/man1/click.1,INSTALLMANPAGES $(DESTDIR)$(mandir))
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click.5 $(DESTDIR)$(mandir)/man5/click.5)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click.o.8 $(DESTDIR)$(mandir)/man8/click.o.8)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-align.1 $(DESTDIR)$(mandir)/man1/click-align.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-combine.1 $(DESTDIR)$(mandir)/man1/click-combine.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-devirtualize.1 $(DESTDIR)$(mandir)/man1/click-devirtualize.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-fastclassifier.1 $(DESTDIR)$(mandir)/man1/click-fastclassifier.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-flatten.1 $(DESTDIR)$(mandir)/man1/click-flatten.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-install.1 $(DESTDIR)$(mandir)/man1/click-install.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-mkmindriver.1 $(DESTDIR)$(mandir)/man1/click-mkmindriver.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-pretty.1 $(DESTDIR)$(mandir)/man1/click-pretty.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-uncombine.1 $(DESTDIR)$(mandir)/man1/click-uncombine.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-undead.1 $(DESTDIR)$(mandir)/man1/click-undead.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-uninstall.1 $(DESTDIR)$(mandir)/man1/click-uninstall.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/click-xform.1 $(DESTDIR)$(mandir)/man1/click-xform.1)
	$(call verbose_cmd,$(INSTALL_DATA) $(srcdir)/elementdoc.7 $(DESTDIR)$(mandir)/man7/elementdoc.7)
	$(call verbose_cmd,$(INSTALL_DATA) testie.1 $(DESTDIR)$(mandir)/man1/testie.1)
	$(call verbose_cmd,$(PERL) $(srcdir)/click-elem2man -l -d $(DESTDIR)$(mandir)/mann -P DEFAULT -p $(top_srcdir) $(top_builddir)/elementmap.xml,CLICK-ELEM2MAN -d $(DESTDIR)$(mandir)/mann)

uninstall: uninstall-man
	/bin/rm -f $(DESTDIR)$(bindir)/click-elem2man
uninstall-man: $(top_builddir)/elementmap.xml
	cd $(DESTDIR)$(mandir)/man1; /bin/rm -f click.1 click-align.1 click-combine.1 click-devirtualize.1 click-fastclassifier.1 click-flatten.1 click-install.1 click-mkmindriver.1 click-pretty.1 click-uncombine.1 click-undead.1 click-uninstall.1 click-xform.1 testie.1
	cd $(DESTDIR)$(mandir)/man5; /bin/rm -f click.5
	cd $(DESTDIR)$(mandir)/man7; /bin/rm -f elementdoc.7
	cd $(DESTDIR)$(mandir)/man8; /bin/rm -f click.o.8
	$(PERL) $(srcdir)/click-elem2man -l -d $(DESTDIR)$(mandir)/mann -P DEFAULT -p $(top_srcdir) -u $(top_builddir)/elementmap.xml

testie.1: $(top_srcdir)/test/testie
	@-if [ ! -f testie.1 -a -f $(srcdir)/testie.1 ]; then \
	   echo $(CP_PRESERVE) $(srcdir)/testie.1 testie.1; \
	   $(CP_PRESERVE) $(srcdir)/testie.1 testie.1; \
	   $(MAKE) testie.1; \
	else \
	   echo $(POD2MAN) -d '' -c '' $(top_srcdir)/test/testie testie.1; \
	   $(POD2MAN) -d '' -c '' $(top_srcdir)/test/testie testie.1; \
	fi

doxygen:
	@if test -z "$(O)"; then echo 1>&2; echo "Run 'make doxygen O=OUTPUTDIRECTORY'" 1>&2; echo 1>&2; false; fi
	@O="$(O)"; \
	if ! expr "$O" : / >/dev/null 2>&1; then O="`pwd`/$O"; fi; \
	sed -e "s#^HTML_OUTPUT.*#HTML_OUTPUT = $O#" \
		-e "s#^GENERATE_LATEX.*#GENERATE_LATEX = NO#" \
		< $(srcdir)/Doxyfile | (cd $(top_srcdir); doxygen -)

always:
	@:

clean:
	rm -f click.aux click.cp click.cps click.dvi click.fn click.fns click.html click.ky click.kys click.pg click.pgs click.tmp click.toc click.tp click.tps click.vr click.vrs *.log
distclean: clean
	-rm -f Makefile

.PHONY: all clean distclean always \
	install install-man uninstall uninstall-man \
	doxygen
