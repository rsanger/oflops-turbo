TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_echo_test.la

libopenflow_echo_test_la_SOURCES= echo_test.c
libopenflow_echo_test_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
