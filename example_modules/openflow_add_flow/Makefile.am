TOP=../..
OFSRC=@openflowsrc@

AM_CXXFLAGS=-std=c++11 -Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_add_flow.la

libopenflow_add_flow_la_SOURCES= add_flow.cpp
libopenflow_add_flow_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm -lrofl_common
