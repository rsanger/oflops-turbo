TOP=../..
OFSRC=@openflowsrc@

AM_CXXFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test -lrofl_common

lib_LTLIBRARIES=libof_packet_in.la

libof_packet_in_la_SOURCES= pktin.cpp
