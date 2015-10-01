TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -I$(TOP)/netfpga-packet-generator-c-library/include \
	-Wshadow # -I$(OFSRC)/lib /testbed/oflops/example_modules/openflow_action_delay
AM_LDFLAGS=-L$(TOP) -L$(OFSRC)/lib/

lib_LTLIBRARIES=libopenflow_action_delay.la

libopenflow_action_delay_la_SOURCES= action_delay.c # msg.h msg.c # vconn.c
libopenflow_action_delay_la_LIBADD=-ldl -lpcap -loflops_test -lopenflow -lm
