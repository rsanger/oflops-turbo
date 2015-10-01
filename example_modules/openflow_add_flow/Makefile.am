TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_add_flow.la

libopenflow_add_flow_la_SOURCES= add_flow.c
libopenflow_add_flow_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
