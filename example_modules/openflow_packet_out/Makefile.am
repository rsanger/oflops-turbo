TOP=../..
OFSRC=@openflowsrc@

AM_CXXFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP)

lib_LTLIBRARIES=libof_packet_out.la

libof_packet_out_la_SOURCES= packet_out.cpp
libof_packet_out_la_LIBADD=-ldl -lpcap -loflops_test -lrofl_common -lm
