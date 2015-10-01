TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -I$(TOP)/netfpga-packet-generator-c-library/include -Wshadow 
AM_LDFLAGS=-L$(TOP)

lib_LTLIBRARIES=libsnmp_queue_delay.la

libsnmp_queue_delay_la_SOURCES= queue_delay.c
libsnmp_queue_delay_la_LIBADD=-ldl -lpcap -loflops_test -lm
