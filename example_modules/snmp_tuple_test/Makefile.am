TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -I$(TOP)/netfpga-packet-generator-c-library/include -Wshadow 
LDFLAGS+=-L$(TOP)

lib_LTLIBRARIES=libsnmp_tuple_test.la

libsnmp_tuple_test_la_SOURCES= tuple_test.c
libsnmp_tuple_test_la_LIBADD=-ldl -lpcap -loflops_test -lm
