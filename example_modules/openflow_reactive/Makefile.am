TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_reactive.la

libopenflow_reactive_la_SOURCES= reactive.c
libopenflow_reactive_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
