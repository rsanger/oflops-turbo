#ifndef CONTEXT_H
#define CONTEXT_H

struct oflops_context;

#include "oflops.h"
#include "test_module.h"
#include "wc_event.h"
#include "channel_info.h"
#include "oflops_snmp.h"
#include <pcap.h>

/**
 * a struct to store all the required configuration parameters for a module run.
 */
typedef struct oflops_context {
  int n_tests;                            /**< number of tests */ 
  int max_tests;	                        /**< maximum size of the tests array */
  struct test_module ** tests;            /**< module struct storage */
  struct test_module * curr_test;         /**< the test that we are currently handling */ 
  uint16_t listen_port;                   /**< the port on which the controller will be listening */

  int snaplen;                            /**< maximum capture size of packet */

  uint8_t of_version;                     /**< The OF version of the current test */
  void *fluid_control;                    /**< libfluid connection */
  int n_channels;                         /**< the number of channel currently used in the current context */
  int max_channels;                       /**< maximum number of channel supported by the channel array */
  struct channel_info * channels;	        /**< an array to store pointer to all channel_info object 
                                            of the control and channel objects */
  uint8_t *of_versions;                   /**< A list of versions */
  size_t nb_of_versions;                  /**< The number of elements in list ^ */

  pthread_t *traffic_gen;                 /** We need this because we might have to call cancel on the thread */
  volatile int end_traffic_generation;    /**< Stop the traffic generation - make sure we do this before we stop the module */
  volatile int end_module;                /**< Stop the module */
  volatile int end_event;                 /**< Stop the event thread */
  /** Encrypted OpenFlow, if these are all set well to tls over the control channel */
  const char *tls_cert;                   /**< The controllers cert 'ctl-cert.pem' */
  const char *tls_privkey;                /**< The controllers private key 'ctl-privkey.pem' */
  const char *tls_trustedcert;            /**< The trusted certificate of the switch's CA 'switchca/cacert.pem' */

  /** SNMP channel configuration
   */
  struct snmp_channel* snmp_channel_info; /**< An array of snmp channel configurations */
  int should_end;                         /**< */
  int should_continue;                    /**< */
  volatile int started;                   /**< Internally set once the trace has started */
  struct wc_queue * timers;               /**< a linked list to store module event objects ordered by time */
  int dump_controller;                    /**< a pcap dump object, to dump pcap packets from the control channel */
  
  char *log;                              /**< a pointer to the logging module */ 
  
  int trafficGen;                         /**< the type of the packet capturing method */
  
  oid **cpuOID;                           /**< an array of cpu oid object */
  size_t *cpuOID_len;                     /**< an array of the length of the cpu oid */
  int cpuOID_count;                       /**< total number of cpu oid in the cpu_oid array */
} oflops_context;

/**
  * \brief possible values of the packet generating mechanism 
  */
enum trafficGenValues {
  USER_SPACE=1, 
  PKTGEN,
  NF_PKTGEN,
};

/**
  * \brief possible mechanism to capture data
  */
enum trafficCapValues {
  PCAP=1,
  NF2,
};

oflops_context * oflops_default_context(void);

int reset_context(oflops_context * ctx);


#endif
