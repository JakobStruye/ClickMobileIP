## The following line supports click-mkmindriver and should not be changed.
## Click linuxmodule driver Makefile ##
SHELL = /bin/sh

subdir := linuxmodule
conf_auxdir = $(top_srcdir)

prefix = /usr/local
exec_prefix = ${prefix}
bindir = /usr/local/bin
sbindir = /usr/local/sbin
libdir = /usr/local/lib
includedir = /usr/local/include
linux_builddir = NONE
linux_srcdir = NONE
linux_makeargs = 

LIB_CXX_OBJS = string.o straccum.o nameinfo.o \
	bitvector.o vectorv.o templatei.o bighashmap_arena.o hashallocator.o \
	ipaddress.o ipflowid.o etheraddress.o \
	packet.o \
	error.o timestamp.o glue.o task.o timer.o atomic.o gaprate.o \
	element.o \
	confparse.o args.o variableenv.o lexer.o elemfilter.o routervisitor.o \
	routerthread.o router.o master.o timerset.o handlercall.o notifier.o \
	integers.o iptable.o \
	driver.o ino.o \
	$(EXTRA_DRIVER_OBJS)

EXTRA_DRIVER_OBJS = 

LIB_C_OBJS = crc32.o in_cksum.o

LINUXMODULE_CXX_OBJS = config.o sched.o module.o clickfs.o skbmgr.o

LINUXMODULE_C_OBJS = kernelversion.o read-pmc.o

STD_ELEMENT_OBJS = addressinfo.o alignmentinfo.o \
	errorelement.o portinfo.o scheduleinfo.o

ifndef MINDRIVER
DRIVER = click
ELEMENTSCONF = elements
KSYMS = ksyms
FINDELEMFLAGS = 
else
DRIVER = $(MINDRIVER)click
ELEMENTSCONF = elements_$(MINDRIVER)
KSYMS = ksyms_$(MINDRIVER)
endif

INSTALLOBJS = $(DRIVER).o proclikefs.o


ifeq (,1)

##########################################################################
## LINUX 2.6								##

KERNELPATH = NONE

ifeq ($(KBUILD_EXTMOD),)
top_srcdir := ..
srcdir := .
top_builddir := ..
else
ifeq (.,.)
top_srcdir := $(src)/..
srcdir := $(src)
else
ifeq ($(patsubst /%,/,.),/)
top_srcdir := ..
srcdir := .
else
top_srcdir := $(obj)/..
srcdir := $(obj)/.
endif
endif
top_builddir := $(obj)/..
endif

CLICK_BUILD_INSTALL = /usr/bin/install -c
CLICK_BUILD_INSTALL_IF_CHANGED = $(CLICK_BUILD_INSTALL) -C
CLICK_BUILD_INSTALL_DATA = $(CLICK_BUILD_INSTALL) -m 644
CLICK_BUILD_INSTALL_DATA_IF_CHANGED = $(CLICK_BUILD_INSTALL_IF_CHANGED) -m 644
CLICKmkinstalldirs = $(conf_auxdir)/mkinstalldirs
CLICK_BUILDTOOL = $(top_builddir)/click-buildtool

CLICK_ELEM2MAKE = $(CLICK_BUILDTOOL) elem2make --linux26

CLICKCC = /usr/bin/gcc -w  -W -Wall
CLICKCXX = /usr/bin/g++ -w  -W -Wall -fno-exceptions -fno-rtti -fpermissive

LINUXCFLAGS = $(shell echo "$(CPPFLAGS) $(CFLAGS) $(LINUXINCLUDE)" \
	"$(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) $(CFLAGS_MODULE)" | sed \
	-e s,-fno-unit-at-a-time,, -e s,-Wstrict-prototypes,, \
	-e s,-Wdeclaration-after-statement,, \
	-e s,-Wno-pointer-sign,, -e s,-fno-common,, \
	-e s,-Werror-implicit-function-declaration,, \
	-e "s,-Iinclude ,-I$(linux_builddir)/include ",g \
	-e "s,-Iinclude2 ,-I$(linux_builddir)/include2 ",g \
	-e s,-Iinclude/,-I$(linux_srcdir)include/,g )
CLICKCPPFLAGS =  -DCLICK_LINUXMODULE
CLICKCFLAGS =  -O2
CLICKCXXFLAGS =  -O2
CLICKDEPCFLAGS = -Wp,-MD,$(depfile)

CLICKDEFS = -DHAVE_CONFIG_H
CLICKINCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(srcdir) -I$(top_srcdir)

CXXCOMPILE = $(CLICKCXX) $(LINUXCFLAGS) $(CLICKCPPFLAGS) $(CLICKCFLAGS) \
	$(CLICKCXXFLAGS) $(CLICKDEFS) $(CLICKINCLUDES)
COMPILE = $(CLICKCC) $(LINUXCFLAGS) $(CLICKCPPFLAGS) $(CLICKCFLAGS) \
	$(CLICKDEFS) $(CLICKINCLUDES)

ifeq ($(PREPROCESS),1)
compile_option = -E
else
compile_option = -c
endif

cmd_shortensyms = $(CLICK_BUILDTOOL) shortensyms $@

quiet_cmd_cxxcompile = CXX $(quiet_modtag) $(subst $(obj)/,,$@)
cmd_cxxcompile = $(CXXCOMPILE) $(CLICKDEPCFLAGS) $(compile_option) -o $@ $< && $(cmd_shortensyms)

quiet_cmd_cxxcompile_nodep = CXX $(quiet_modtag) $(subst $(obj)/,,$@)
cmd_cxxcompile_nodep = $(CXXCOMPILE) $(compile_option) -o $@ $< && $(cmd_shortensyms)

quiet_cmd_ccompile = CC $(quiet_modtag) $(subst $(obj)/,,$@)
cmd_ccompile = $(COMPILE) $(CLICKDEPCFLAGS) $(compile_option) -o $@ $<

quiet_cmd_ccompile_nodep = CC $(quiet_modtag) $(subst $(obj)/,,$@)
cmd_ccompile_nodep = $(COMPILE) $(compile_option) -o $@ $<

ifeq ($(V),1)
x_verbose_cmd = $(1) $(3)
verbose_cmd = $(1) $(3)
else
x_verbose_cmd = $(if $(2),/bin/echo ' ' $(2) $(3) &&,) $(1) $(3)
verbose_cmd = @$(x_verbose_cmd)
endif

EXTRA_CFLAGS = $(CLICKCPPFLAGS) $(CLICKCFLAGS) $(CLICKDEFS) $(CLICKINCLUDES)

obj-m += $(INSTALLOBJS)

proclikefs-objs = proclikefsmod.o

KSYM_OBJS = $(LIB_C_OBJS) $(LIB_CXX_OBJS) $(STD_ELEMENT_OBJS) \
	$(ELEMENT_OBJS) $(LINUXMODULE_C_OBJS) $(LINUXMODULE_CXX_OBJS)
INCLUDE_KSYMS = yes
ifeq ($(INCLUDE_KSYMS),yes)
$(DRIVER)-objs = $(KSYM_OBJS) $(ELEMENTSCONF).o $(KSYMS).o
else
$(DRIVER)-objs = $(KSYM_OBJS) $(ELEMENTSCONF).o
endif

all: Makefile $(ELEMENTSCONF).mk $(ELEMENTSCONF).cc always
	$(MAKE) -C $(KERNELPATH) M=$(shell pwd) $(linux_makeargs) modules


$(addprefix $(obj)/,$(LIB_CXX_OBJS)): $(obj)/%.o : $(top_srcdir)/lib/%.cc
	$(call if_changed_dep,cxxcompile)

$(addprefix $(obj)/,$(LIB_C_OBJS)): $(obj)/%.o : $(top_srcdir)/lib/%.c
	$(call if_changed_dep,ccompile)

$(addprefix $(obj)/,$(LINUXMODULE_CXX_OBJS)): $(obj)/%.o : $(srcdir)/%.cc
	$(call if_changed_dep,cxxcompile)

$(addprefix $(obj)/,$(LINUXMODULE_C_OBJS)): $(obj)/%.o : $(srcdir)/%.c
	$(call if_changed_dep,ccompile)

$(addprefix $(obj)/,$(STD_ELEMENT_OBJS)): $(obj)/%.o : $(top_srcdir)/elements/standard/%.cc
	$(call if_changed_dep,cxxcompile)

$(obj)/$(ELEMENTSCONF).o : $(obj)/$(ELEMENTSCONF).cc
	$(call if_changed_dep,cxxcompile)

$(obj)/proclikefsmod.o : $(srcdir)/proclikefs.c
	$(call if_changed_rule,cc_o_c)

ifneq ($(MAKECMDGOALS),clean)
-include $(obj)/$(ELEMENTSCONF).mk
endif

$(obj)/$(KSYMS).c: $(addprefix $(obj)/,$(KSYM_OBJS)) $(top_builddir)/click-buildtool $(addprefix $(obj)/,$(ELEMENTSCONF).mk)
	$(call verbose_cmd,$(top_builddir)/click-buildtool ksyms -C $(obj) -x kernelversion.o $(KSYM_OBJS) >,CREATE,$(obj)/$(KSYMS).c)
$(obj)/$(KSYMS).o: $(obj)/$(KSYMS).c
	$(call if_changed_dep,ccompile)

# Don't install in Linux directories for now
# $(MAKE) -C $(KERNELPATH) M=$(shell pwd) modules_install
install: install-local install-include
install-local: Makefile $(ELEMENTSCONF).mk $(ELEMENTSCONF).cc all
	$(CLICKmkinstalldirs) $(DESTDIR)$(libdir)
	for i in $(patsubst %.o,%.ko,$(INSTALLOBJS)); do $(CLICK_BUILD_INSTALL_DATA) $$i $(DESTDIR)$(libdir)/$$i; done
	$(CLICK_BUILD_INSTALL_DATA) Module.symvers $(DESTDIR)$(libdir)/click.symvers
install-include:
	/bin/rm -f .install-include*
	$(CLICKmkinstalldirs) $(DESTDIR)$(includedir)/click-linuxmodule
	(cd $(DESTDIR)$(includedir)/click-linuxmodule; find . -type d -print | grep /) >.install-include0 || true
	(cd $(top_builddir)/include/click-linuxmodule; find . -type d -print | grep /) >.install-include1 || true
	cat .install-include0 .install-include1 | sort | uniq -u >.install-include2
	cat .install-include0 .install-include2 | sort | uniq -d | sed 's	^\.\(.*\)	'"$(DESTDIR)$(includedir)/click-linuxmodule"'\1	' | xargs -L 1 /bin/rm -rf
	cat .install-include1 .install-include2 | sort | uniq -d | sed 's	^\.\(.*\)	'"$(DESTDIR)$(includedir)/click-linuxmodule"'\1	' | xargs -L 1 $(CLICKmkinstalldirs)
	/bin/rm -f .install-include*
	(cd $(DESTDIR)$(includedir)/click-linuxmodule; find . -type f -print | grep /) >.install-include0 || true
	(cd $(top_builddir)/include/click-linuxmodule; find . -type f -print | grep /) >.install-include1 || true
	cat .install-include0 .install-include1 | sort | uniq -u >.install-include2
	cat .install-include0 .install-include2 | sort | uniq -d | sed 's	^\.\(.*\)	'"$(DESTDIR)$(includedir)/click-linuxmodule"'\1	' | xargs -L 1 /bin/rm -f
	cat .install-include1 | sed 's	^\.\(.*\)	'"$(top_builddir)/include/click-linuxmodule"'\1'" $(DESTDIR)$(includedir)/click-linuxmodule"'\1	' | xargs -L 1 $(CLICK_BUILD_INSTALL_DATA_IF_CHANGED)
	/bin/rm -f .install-include*
install-man:
	@:
uninstall:
	for i in $(patsubst %.o,%.ko,$(INSTALLOBJS)); do /bin/rm -f $(DESTDIR)$(libdir)/$$i; done
	(cd $(top_builddir)/include/click-linuxmodule; find . -type f -print) | grep / | sed 's	^\.\(.*\)	'"$(top_builddir)/include/click-linuxmodule"'\1'" $(DESTDIR)$(includedir)/click-linuxmodule"'\1	' | xargs -L 1 rm -f

else

##########################################################################
## LINUX 2.4								##

top_srcdir := ..
srcdir := .
top_builddir := ..

VPATH = .:$(top_srcdir)/lib:$(top_srcdir)/$(subdir):$(top_srcdir)/elements/standard

CC = /usr/bin/gcc -w  -W -Wall
CPP = /usr/bin/gcc -E
CXX = /usr/bin/g++ -w  -W -Wall -fno-exceptions -fno-rtti -fpermissive
CXXCPP = /usr/bin/g++ -E
LD = ld
STRIP = strip
INSTALL = /usr/bin/install -c
INSTALL_DATA = $(INSTALL) -m 644
mkinstalldirs = $(conf_auxdir)/mkinstalldirs
CLICK_ELEM2MAKE = $(top_builddir)/click-buildtool elem2make

ifeq ($(V),1)
ccompile = $(COMPILE) $(DEPCFLAGS) $(1)
ccompile_nodep = $(COMPILE) $(1)
cxxcompile = $(CXXCOMPILE) $(DEPCFLAGS) $(1)
cxxcompile_nodep = $(CXXCOMPILE) $(1)
else
ccompile = @/bin/echo ' ' $(2) $< && $(COMPILE) $(DEPCFLAGS) $(1)
ccompile_nodep = @/bin/echo ' ' $(2) $< && $(COMPILE) $(1)
cxxcompile = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(DEPCFLAGS) $(1)
cxxcompile_nodep = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(1)
endif

.SUFFIXES:
.SUFFIXES: .c .cc .o .S .s .i .ii

.c.o:
	$(call ccompile,-c $< -o $@,CC)
.c.i:
	$(call ccompile_nodep,-E $< > $@,CPP)
.s.o:
	$(call ccompile,-c $< -o $@,ASM)
.S.o:
	$(call ccompile,-c $< -o $@,ASM)
.cc.o:
	$(call cxxcompile,-c $< -o $@,CXX)
.cc.s:
	$(call cxxcompile_nodep,-S $< -o $@,CXX -S)
.cc.ii:
	$(call cxxcompile_nodep,-E $< > $@,CXXCPP)


OBJS = $(LIB_CXX_OBJS) $(LIB_C_OBJS) $(STD_ELEMENT_OBJS) $(ELEMENT_OBJS) \
	$(LINUXMODULE_CXX_OBJS) $(LINUXMODULE_C_OBJS) $(ELEMENTSCONF).o

CPPFLAGS =  -DCLICK_LINUXMODULE
CFLAGS =  -O2
CXXFLAGS =  -O2
DEPCFLAGS = -MD -MP

DEFS = -DHAVE_CONFIG_H
INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(srcdir) -I$(top_srcdir)
LDFLAGS = 
LIBS = 

CXXCOMPILE = $(CXX) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) $(CXXFLAGS)
CXXLD = $(CXX)
CXXLINK = $(CXXLD) $(CXXFLAGS) $(LDFLAGS) -o $@
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(CFLAGS) $(LDFLAGS) -o $@

all: $(INSTALLOBJS)

ifneq ($(MAKECMDGOALS),clean)
-include $(ELEMENTSCONF).mk
endif

$(DRIVER).o: Makefile $(OBJS)
	$(LD) -r -o $(DRIVER).o $(OBJS)
	$(STRIP) -g $(DRIVER).o

proclikefs.o: proclikefs.c Makefile
	$(COMPILE) -D__KERNEL__ -DMODULE $(DEPCFLAGS) -c $< -o $@

DEPFILES := $(wildcard *.d)
ifneq ($(DEPFILES),)
include $(DEPFILES)
endif

install: install-local
install-local: $(INSTALLOBJS)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	for i in $(INSTALLOBJS); do $(INSTALL_DATA) $$i $(DESTDIR)$(libdir)/$$i; done
install-include:
	@:
install-man:
	@:
uninstall:
	for i in $(INSTALLOBJS); do /bin/rm -f $(DESTDIR)$(libdir)/$$i; done

endif


##########################################################################
## ANY LINUX								##

elemlist:
	@/bin/rm -f elements.conf
	@$(MAKE) elements.conf
elements.conf: $(top_builddir)/config.status $(top_builddir)/click-buildtool
	echo "linuxmodule  analysis app aqm ethernet etherswitch icmp ip local simple standard tcpudp test threads" | $(top_builddir)/click-buildtool findelem -r linuxmodule -p $(top_srcdir) -X $(srcdir)/elements.exclude $(FINDELEMFLAGS) > elements.conf
$(ELEMENTSCONF).mk: $(ELEMENTSCONF).conf $(top_builddir)/click-buildtool
	$(CLICK_ELEM2MAKE) -x "$(STD_ELEMENT_OBJS)" < $(ELEMENTSCONF).conf > $(ELEMENTSCONF).mk
$(ELEMENTSCONF).cc: $(ELEMENTSCONF).conf $(top_builddir)/click-buildtool
	$(top_builddir)/click-buildtool elem2export < $(ELEMENTSCONF).conf > $(ELEMENTSCONF).cc
	@rm -f $(ELEMENTSCONF).d

Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

always:
	@:

clean:
	-rm -f *~ *.d *.o *.mod.c *.ko
	-rm -f .version .*.o.flags .*.o.d .*.o.cmd .*.ko.cmd
	-rm -f $(ELEMENTSCONF).mk $(ELEMENTSCONF).cc $(KSYMS).c elements.conf
	-rm -rf Module.symvers .tmp_versions modules.order
distclean: clean
	-rm -f Makefile

.PHONY: always all clean distclean elemlist \
	install install-local install-include install-man uninstall
