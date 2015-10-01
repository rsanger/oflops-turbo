TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_flow_stats.la

libopenflow_flow_stats_la_SOURCES= flow_stats.c
libopenflow_flow_stats_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
