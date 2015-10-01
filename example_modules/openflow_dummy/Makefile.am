TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_dummy.la

libopenflow_dummy_la_SOURCES= dummy.c # vconn.c
libopenflow_dummy_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow
