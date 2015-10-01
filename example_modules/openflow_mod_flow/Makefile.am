TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include # -I$(OFSRC)/lib
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_mod_flow.la

libopenflow_mod_flow_la_SOURCES= mod_flow.c
libopenflow_mod_flow_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
