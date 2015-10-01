TOP=../..
OFSRC=@openflowsrc@

AM_CXXFLAGS=-std=c++11 -Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP)

lib_LTLIBRARIES=libof_packet_in_out.la

libof_packet_in_out_la_SOURCES= pkt_in_out.cpp
libof_packet_in_out_la_LIBADD=-ldl -lpcap -loflops_test -lrofl_common -lm
