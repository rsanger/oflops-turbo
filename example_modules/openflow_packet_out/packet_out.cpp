#include <rofl_common.h>
#include <rofl/common/crofbase.h>
#include <rofl/common/openflow/messages/cofmsg.h>

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <limits.h>
#include <math.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>


#include <test_module.h>

#include "log.h"
#include "msg.h"
#include "traffic_generator.h"

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define SNMPGET "snmp get"
#define SND_PKT "send packet"
#define FORCE_START "force start"

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

#undef OFP_VERSION

// calculated sending time interval (measured in usec). 
uint64_t probe_snd_interval;

static char *cli_param;
static int pkt_size = 1500;
static int print = 0;
static int test_duration = 60;
static volatile int started = 0;

// Some constants to help me with conversions
static const uint64_t sec_to_usec = 1000000;
static const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

//local mac
static char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  uint32_t ip, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

TAILQ_HEAD(tailhead, entry) head;
static int rcv_pkt_count = 0;

static uint8_t *b = NULL;
struct iphdr *ip;
struct pktgen_hdr *pktgen;
static int pkt_counter;

int generate_pkt_out(struct oflops_context * ctx, struct timeval *now);

// FIXME: this has an ugly part, where we write directly to the tcp socket. need 
// to remove that in a later release

/**
 * \defgroup openflow_packet_out openflow packe out
 * \ingroup modules
 * A module to benchmark the performance of the packet out functionality of an
 * openflow implementation
 *
 * Parameters:
 *
 *    - pkt_size:  This parameter can be used to control the length of the
 *   packets of the measurement probe. It allows indirectly to adjust the packet
 * throughput of the experiment. (default 1500 bytes)
 *    - probe_snd_interval: This parameter controls the data rate of the
 * measurement probe, in Mbps. (default 10Mbps)
 *    - print: This parameter defines if the measurement module prints
 *   extended per packet measurement information. The information is printed in log
 *   file.
 *   - duration: The length of the test in seconds, default 60 seconds
 * 
 * Copyright (C) University of Cambridge, Computer Lab, 2011
 * \author crotsos
 * \date September, 2009
 * 
 */

/**
 * \ingroup openflow_packet_out
 * \return name of module
 */
const char * name()
{
  return "Pkt_out_module";
}


const uint8_t *get_openflow_versions() {
    static uint8_t of_versions[] = {0x01, 0x04, 0x0};
    return of_versions;
}

/**
 * \ingroup openflow_packet_out
 * Initialization
 * \param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) {
  struct timeval now;
  gettimeofday(&now, NULL);
  char msg[1024];
  uint8_t buf[1024];

  //init measurement queue
  TAILQ_INIT(&head); 

  started = 0;

  snprintf(msg, 1024,  "Intializing module %s", name());

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now, GENERIC_MSG, cli_param);

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);

  int len;
  rofl::openflow::cofflowmod *fm;

  //send a message to clean up flow tables. 
  printf("cleaning up flow table...\n");
  rofl::openflow::cofmsg_flow_mod del_flows(ctx->of_version, 1);
  fm = &del_flows.set_flowmod();
  fm->set_command(rofl::openflow::OFPFC_DELETE);
  fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
  len = del_flows.length();
  memset(buf, 0, len); // ZERO buffer some devices check padding is zero
  del_flows.pack(buf, 1000);
  oflops_send_of_mesgs(ctx, (char *)buf, len);

  rofl::openflow::cofmsg_barrier_request barrier(ctx->of_version, 1450);
  len = barrier.length();
  barrier.pack(buf, 1000);
  oflops_send_of_mesgs(ctx, (char *)buf, len);

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, const_cast<char *>(SNMPGET));

  oflops_schedule_timer_event(ctx,&now, const_cast<char *>(FORCE_START));

  return 0;
}

/** Handle timer  
 * \ingroup openflow_packet_out
 * \param ctx pointer to opaque context
 * \param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  struct timeval now;
  char * str;
  int i;
  str = (char *) te->arg;

  if(!strcmp(str,SNMPGET)) {
    for(i=0;i<ctx->cpuOID_count;i++) {
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
    }
    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }  
    gettimeofday(&now, NULL);
    add_time(&now, 10, 0);
    oflops_schedule_timer_event(ctx,&now, const_cast<char *>(SNMPGET));
  } else if(!strcmp(str,BYESTR)) {
    oflops_end_test(ctx,1);
  } else if(!strcmp(str,SND_PKT)) {
    oflops_gettimeofday(ctx, &now);
    generate_pkt_out(ctx, &now);
    gettimeofday(&now, NULL);
    add_time(&now, probe_snd_interval/sec_to_usec, probe_snd_interval%sec_to_usec);
    oflops_schedule_timer_event(ctx,&now, const_cast<char *>(SND_PKT));
  } else if (!strcmp(str,FORCE_START)) {
    if (started == false) {
      struct timer_event new_te;
      gettimeofday(&now, NULL);
      oflops_log(now, GENERIC_MSG, "Warning barrier message not received within 1 sec. Starting packet-outs anyway");
      started = true;

      new_te.arg = const_cast<char *>(SND_PKT);
      started = 1;
      handle_timer_event(ctx, &new_te);
      //Schedule end
      add_time(&now, test_duration, 0);
      oflops_schedule_timer_event(ctx,&now, const_cast<char *>(BYESTR));
    }
  } else
    fprintf(stderr, "Unknown timer event: %s", str);
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int 
destroy(oflops_context *ctx) {
  struct entry *np, *lp;
  size_t i;
  double mean, median, sd;
  double loss;
  char msg[1024];
  double *data;
  struct timeval now;

  gettimeofday(&now, NULL);

  data = (double *) xmalloc(rcv_pkt_count*sizeof(double));
  i=0;
  for (np = head.tqh_first; np != NULL;) {
    data[i++] = (double)time_diff(&np->snd, &np->rcv);
    if(print) {
      snprintf(msg, 1024, "%lu.%06lu:%lu.%06lu:%d:%d",
          np->snd.tv_sec, np->snd.tv_usec,
          np->rcv.tv_sec, np->rcv.tv_usec,
          np->id, time_diff(&np->snd, &np->rcv));
      oflops_log(now, OFPT_PACKET_IN_MSG, msg);
    }
    lp = np;
    np = np->entries.tqe_next;
    free(lp);
  }

  if(i > 0) {
    gsl_sort (data, 1, i);

    //calculating statistical measures
    mean = gsl_stats_mean(data, 1, i);
    sd = gsl_stats_sd(data, 1, i);
    median = gsl_stats_median_from_sorted_data (data, 1, i);
    loss = (double)i/(double)pkt_counter;

    snprintf(msg, 1024, "statistics:%f:%f:%f:%f:%zd", mean, median,
        sd, loss, i);
    printf("statistics:%f:%f:%f:%f:%zd\n", mean, median, sd,
           loss, i);
    oflops_log(now, GENERIC_MSG, msg);
  }
  free(data);
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int i;
  char msg[1024], log_buf[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, 1024, vars->name, vars->name_length, vars);


    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
          (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
        snprintf(log_buf, 1024, "cpu:%ld:%ld:%s",
            se->pdu->reqid, 
            vars->name[ vars->name_length - 1],msg);
        oflops_log(now, SNMP_MSG, log_buf);
      }
    } 

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
          (memcmp(vars->name, ctx->channels[i].inOID,  
                  ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
        snprintf(log_buf, 1024, "port:rx:%ld:%d:%s",  
            se->pdu->reqid, 
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, log_buf);
        break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
          (memcmp(vars->name, ctx->channels[i].outOID,  
                  ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
        snprintf(log_buf, 1024, "port:tx:%ld:%d:%s",  
            se->pdu->reqid, 
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, log_buf);
        break;
      }
    } //for
  }
  return 0;
}

/**
 * Initialization code with parameters
 * \ingroup openflow_packet_out
 * \param ctx 
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  //init counters
  gettimeofday(&now, NULL);
  cli_param = strdup(config_str);

  while(*config_str == ' ') {
    config_str++;
  }
  param = config_str;
  while(1) {
    pos = index(param, ' ');

    if((pos == NULL)) {
      if (*param != '\0') {
        pos = param + strlen(param);
      } else
        break;
    } else {
        *pos='\0';
        pos++;
    }
    value = index(param,'=');
    *value = '\0';
    value++;
    //fprintf(stderr, "param = %s, value = %s\n", param, value);
    if(value != NULL) {
      if(strcmp(param, "pkt_size") == 0) {
        //parse int to get pkt size
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
          perror_and_exit("Invalid packet size value", 1);
      }
      else if(strcmp(param, "probe_snd_interval") == 0) {
        //parse int to get measurement probe rate
        probe_snd_interval = strtol(value, NULL, 0);
        if( probe_snd_interval  < 500)
          perror_and_exit("Invalid probe rate param(larger than 100 microsec", 1);
      }
      else if(strcmp(param, "duration") == 0) {
        test_duration = strtol(value, NULL, 0);
        if (test_duration <= 0)
          perror_and_exit("Invalid duration, value must be larger than 0", 1);
      }
      else if(strcmp(param, "print") == 0) {
        //parse int to get pkt size
        print = strtol(value, NULL, 0);
      } else {
        fprintf(stderr, "Invalid parameter:%s\n", param);
      }
      param = pos;
    }
  } 

  //calculate sendind interval
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes)\n", 
      (uint32_t)probe_snd_interval, (uint32_t)pkt_size);
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int
generate_pkt_out(struct oflops_context * ctx,struct timeval *now) {
    struct ether_header *ether;
    struct udphdr *udp;
    uint8_t buf[5000];

    rofl::openflow::cofmsg_packet_out pkt_out(ctx->of_version);
    rofl::cpacket &pkt = pkt_out.set_packet();


  if(b == NULL) {
    b = (uint8_t *)xmalloc(pkt_size*sizeof(char));

    //setting up the ethernet header
    ether = (struct ether_header *) b;
    memcpy(ether->ether_shost, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN);
    memcpy(ether->ether_dhost, local_mac, ETH_ALEN);
    ether->ether_type = htons(ETHERTYPE_IP);

    //setting up the ip header
    ip = (struct iphdr *)(b + sizeof(struct ether_header));
    ip->protocol=1;
    ip->ihl=5;
    ip->version=4;
    ip->ttl = 100;
    ip->protocol = IPPROTO_UDP; //udp protocol
    ip->saddr = inet_addr("10.1.1.1"); 
    ip->daddr = inet_addr("192.168.3.0"); //test.nw_dst;
    ip->tot_len = htons(pkt_size - sizeof(struct ether_header));

    //setting up the udp header
    udp = (struct udphdr *)(b + sizeof(struct ether_header) + sizeof(struct iphdr));
    udp->source = htons(8080);
    udp->dest = htons(8080);
    udp->len = htons(pkt_size - sizeof(struct ether_header) 
        - sizeof(struct iphdr));

    //setting up pktgen header
    pktgen = (struct pktgen_hdr *)(b + sizeof(struct ether_header) +
        sizeof(struct iphdr) + sizeof(struct udphdr));

    pktgen->magic = htonl(0xbe9be955);
  }
  pkt_out.set_xid(pkt_counter);
  pktgen->tv_sec = htonl(now->tv_sec);
  pktgen->tv_usec = htonl(now->tv_usec);
  pktgen->seq_num = htonl(++pkt_counter);
  ip->check = htons(0x87c5);
  pkt.assign(b, pkt_size);
  pkt_out.set_in_port(rofl::openflow::OFPP_CONTROLLER);
  pkt_out.set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
  rofl::openflow::cofaction_output &output = pkt_out.set_actions().add_action_output(rofl::cindex(0));
  pkt_out.set_actions().set_version(ctx->of_version);
  output.set_port_no(ctx->channels[OFLOPS_DATA1].of_port);
  output.set_max_len(rofl::openflow13::OFPCML_NO_BUFFER);

  int len = pkt_out.length();
  pkt_out.pack(buf, 5000);
  oflops_send_of_mesgs(ctx, (char *)buf, len);

  return 1;
}

/** Register pcap filter.
 * \ingroup openflow_packet_out
 * \param ctx pointer to opaque context
 * \param ofc enumeration of channel that filter is being asked for
 * \param filter filter string for pcap
 * \param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
  if (ofc == OFLOPS_DATA1) {
    return snprintf(filter,buflen,"udp");
  }
  return 0;
}

/** Handle pcap event.
 * \ingroup openflow_packet_out
 * \param ctx pointer to opaque context
 * \param pe pcap event
 * \param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event *pe,
    oflops_channel_name ch) {
  struct flow fl;
  struct pktgen_hdr *pkt;
  if (ch == OFLOPS_DATA1) {
    pkt = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, 
        pe->pcaphdr.caplen, &fl);

    if( fl.dl_type != 0x0800) {
      printf("Invalid eth type %x\n",fl.dl_type );
      return 0;
    }

    pkt = (struct pktgen_hdr *)(pe->data + sizeof(struct ether_header) +
        sizeof(struct iphdr) + sizeof(struct udphdr));    
    struct entry *n1 = (struct entry *) malloc(sizeof(struct entry));
    n1->snd.tv_sec = pkt->tv_sec;
    n1->snd.tv_usec = pkt->tv_usec;
    memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
    n1->ip = fl.nw_src;
    n1->id = pkt->seq_num;
    rcv_pkt_count++;
    TAILQ_INSERT_TAIL(&head, n1, entries);
  }
  return 0;
}

/**
 * \ingroup openflow_packet_out
 */
int
handle_traffic_generation (oflops_context *ctx) {

  start_traffic_generator(ctx);
  return 1;
}
}

#define OF_MESSAGE(version, type) \
    (version == rofl::openflow10::OFP_VERSION ? rofl::openflow10::OFPT_ ##type : \
    version == rofl::openflow12::OFP_VERSION ? rofl::openflow12::OFPT_ ##type : \
    version == rofl::openflow13::OFP_VERSION ? rofl::openflow13::OFPT_ ##type : \
                                               (assert(0), 0) \
    )

extern "C" void of_message (struct oflops_context *ctx, uint8_t of_version, uint8_t type, void *data, size_t len) {
    if (0 && type == OF_MESSAGE(of_version, BARRIER_REPLY)) {
        struct timeval now;
        struct timer_event te;
        te.arg = const_cast<char *>(SND_PKT);
        started = 1;
        handle_timer_event(ctx, &te);
        //Schedule end
        gettimeofday(&now, NULL);
        add_time(&now, test_duration, 0);
        oflops_schedule_timer_event(ctx,&now, const_cast<char *>(BYESTR));
    } else {
        struct timeval now;
        char buf[200];
        oflops_gettimeofday(ctx, &now);
        snprintf(buf, sizeof(buf), "Got unexpected OF message %d %s", (int) type, rofl::openflow::cofmsg::type2desc(of_version,type));
        oflops_log(now, GENERIC_MSG, buf);
    }
}
