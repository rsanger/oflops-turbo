TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_aggr_flow_stats.la

libopenflow_aggr_flow_stats_la_SOURCES= aggr_flow_stats.c
libopenflow_aggr_flow_stats_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
