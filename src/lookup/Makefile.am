EXTRA_DIST = README

if ENABLE_EXPERIMENTAL
	
AM_CFLAGS = @KRB5_CFLAGS@
LDADD = liblookup.la ../liboddcommon.la @LDAP_LIBS@ @SASL_LIBS@ @KRB5_LIBS@

noinst_PROGRAMS = lookup
noinst_LTLIBRARIES = liblookup.la
liblookup_la_SOURCES = \
	common.h \
	ads.c \
	cyrus.c cyrus.h \
	scrape.c scrape.h \
	plain.c plain.h \
	gssapi.c gssapi.h
lookup_SOURCES = lookup.c

endif
