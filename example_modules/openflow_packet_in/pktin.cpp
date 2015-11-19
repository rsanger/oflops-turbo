#include <rofl_common.h>
#include <rofl/common/crofbase.h>
#include <rofl/common/openflow/messages/cofmsg.h>
#include <mutex>
#include <condition_variable>

extern "C"{
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

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500
#define MATCH_COOKIE 0xDEADBEEF
static uint64_t bad_match_cookie = 0xF000F000;

#undef OFP_VERSION

// Probe rate in packets per second
static uint64_t probe_snd_rate = 1000;

// Number of flows to send. 
static char *cli_param;
static int pkt_size = 1500;
static uint32_t pkt_in_count;
/* The number of pkt in with the correct cookie */
static uint32_t pkt_in_cookie_count;
static std::string print;
static std::ofstream csv_output;
static int test_duration = 60;
static int extra_rules = 0;
static uint16_t max_buf_size = rofl::openflow13::OFPCML_NO_BUFFER;
static uint32_t first_seq;
static uint32_t last_seq;
static long double calculated_mean;
static int table_id = 0;

// Some constants to help me with conversions
static const uint64_t sec_to_usec = 1000000;
static const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

struct entry {
  struct timeval snd,rcv;
  int id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(tailhead, entry) head;

static std::mutex barrier_lock;
static std::condition_variable barrier_cond;
static bool ready_to_generate;

/**
 * \defgroup openflow_packet_in openflow packet in
 * \ingroup modules
 * A module to benchmark the packet_in functionality of an openflow implementation.
 * the module generates traffic at user specified rates and measures the delay to receive
 * packets on the control channel. 
 *
 * Parameters:
 *
 *  - pkt_size:  This parameter can be used to control the length of the
 *    packets created in bytes. (default 1500 bytes)
 *  - probe_snd_rate: This parameter controls the data rate of the
 *    measurement probe in packets per second. The default is 1000.
 *  - print: This parameter enables the measurement module to save
 *    extended per packet measurement information to the given csv file.
 *    (defaults to no file)
 *  - max_buf_size: Set the maximum packet-in size, default no buffer (0)
 *  - duration: The length of the test in seconds, default 60 seconds
 *  - extra_rules: Adds the requested number of rules at a higher
 *    priority to the one being hit.
 *  - table: The ID of the table to put rules into, note only this table is
 *    cleared at the start of the test, allowing goto's in other tables to
 *    persist.
 * 
 * Copyright (C) University of Cambridge, Computer Lab, 2011
 * \author crotsos
 * \date March, 2011
 * 
 */

/**
 * \ingroup openflow_packet_in
 * get the name of the module
 * \return name of module
 */
const char * name()
{
  return "Pkt_in_module";
}

const uint8_t *get_openflow_versions() {
    static uint8_t of_versions[] = {0x01, 0x04, 0x0};
    return of_versions;
}


/**
 * \ingroup openflow_packet_in
 * empty flow tables and shcedule events.
 * \param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) {
  struct timeval now;
  gettimeofday(&now, NULL);
  uint8_t buf[1024];
  char msg[1024];
  int len;
  rofl::openflow::cofflowmod *fm;

  //init measurement queue
  TAILQ_INIT(&head); 

  ready_to_generate = false;
  first_seq = (uint32_t)-1;
  last_seq = 0;
  pkt_in_count = 0;
  pkt_in_cookie_count = 0;
  calculated_mean = 0;

  snprintf(msg, sizeof(msg),  "Intializing module %s", name());
  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now, GENERIC_MSG, cli_param);
  snprintf(msg, sizeof(msg),  "OpenFlow version %d in use", (int)ctx->of_version);
  oflops_log(now, GENERIC_MSG, msg);
  std::cout<<msg<<std::endl;
  if (ctx->n_channels < 2) {
      std::cerr<<"Module requires at least 1 data channel"<<std::endl;
      oflops_log(now, GENERIC_MSG, "Module requires at least 1 data channel");
      assert(ctx->n_channels >= 2);
  }

  //send a message to clean up flow tables.
  rofl::openflow::cofmsg_flow_mod del_flows(ctx->of_version, 1);
  fm = &del_flows.set_flowmod();
  fm->set_command(rofl::openflow::OFPFC_DELETE);
  fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
  fm->set_table_id(table_id);
  len = del_flows.length();
  memset(buf, 0, len); // ZERO buffer some devices check padding is zero
  del_flows.pack(buf, 1000);
  oflops_send_of_mesgs(ctx, (char *)buf, len);

  for (int i = 0; i < extra_rules ; ++i) {
      rofl::caddress_in4 mask = rofl::caddress_in4("255.255.255.0");
      rofl::caddress_in4 address = rofl::caddress_in4("200.0.0.0");
      rofl::openflow::cofmsg_flow_mod send_to_controller(ctx->of_version, 2);

      address.set_addr_hbo(address.get_addr_hbo() + (i *256));

      fm = &send_to_controller.set_flowmod();
      fm->set_command(rofl::openflow::OFPFC_ADD);
      fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
      fm->set_table_id(table_id);
      fm->set_priority(15000);
      fm->set_match().set_in_port(ctx->channels[OFLOPS_DATA1].of_port);
      fm->set_match().set_ip_proto(17);
      fm->set_match().set_eth_type(0x0800);
      if (ctx->of_version == rofl::openflow10::OFP_VERSION)
        fm->set_match().set_nw_dst(address, mask);
      else
        fm->set_match().set_ipv4_dst(address, mask);
      fm->set_cookie(bad_match_cookie++);
      rofl::openflow::cofactions &actions = ctx->of_version <= rofl::openflow10::OFP_VERSION?
                  fm->set_actions():
                  fm->set_instructions().set_inst_apply_actions().set_actions();

      rofl::openflow::cofaction_output &output = actions.add_action_output(rofl::cindex(0));
      output.set_port_no(rofl::openflow::OFPP_CONTROLLER);
      output.set_max_len(max_buf_size);
      len = send_to_controller.length();
      memset(buf, 0, len); // ZERO buffer some devices check padding is zero
      send_to_controller.pack(buf, 1000);
      oflops_send_of_mesgs(ctx, (char *)buf, len);
  }

  rofl::openflow::cofmsg_flow_mod send_to_controller(ctx->of_version, 2);
  fm = &send_to_controller.set_flowmod();
  fm->set_command(rofl::openflow::OFPFC_ADD);
  fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
  fm->set_table_id(table_id);
  fm->set_priority(10000);
  fm->set_match().set_in_port(ctx->channels[OFLOPS_DATA1].of_port);
  fm->set_match().set_ip_proto(17);
  fm->set_match().set_eth_type(0x0800);
  fm->set_cookie(MATCH_COOKIE);
  rofl::openflow::cofactions &actions = ctx->of_version <= rofl::openflow10::OFP_VERSION?
              fm->set_actions():
              fm->set_instructions().set_inst_apply_actions().set_actions();

  rofl::openflow::cofaction_output &output = actions.add_action_output(rofl::cindex(0));
  output.set_port_no(rofl::openflow::OFPP_CONTROLLER);
  output.set_max_len(max_buf_size);
  len = send_to_controller.length();
  memset(buf, 0, len); // ZERO buffer some devices check padding is zero
  send_to_controller.pack(buf, 1000);
  oflops_send_of_mesgs(ctx, (char *)buf, len);

  rofl::openflow::cofmsg_barrier_request barrier(ctx->of_version, 1450);
  len = barrier.length();
  barrier.pack(buf, 1000);
  oflops_send_of_mesgs(ctx, (char *)buf, len);

  if (!print.empty()) {
    snprintf(msg, sizeof(msg),  "Opening output file %s", print.c_str());
    oflops_log(now, GENERIC_MSG, msg);
    csv_output.open(print.c_str());
    csv_output<<std::setfill('0');
  }

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx, &now, const_cast<char *>(SNMPGET));

  return 0;
}

/** 
 * \ingroup openflow_packet_in
 * Handle timer events
 * - BYESTR: terminate module execution
 * - SNMPGET: request SNMP counters
 * \param ctx pointer to opaque context
 * \param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  struct timeval now;
  char * str;
  int i;

  gettimeofday(&now,NULL);
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
    add_time(&now, 1, 0);
    oflops_schedule_timer_event(ctx, &now, const_cast<char *>(SNMPGET));
  } else if(!strcmp(str,BYESTR)) {
    oflops_end_test(ctx,1);
  } else
    fprintf(stderr, "Unknown timer event: %s", str);
  return 0;
}

/**
 * \ingroup openflow_packet_in
 * Calcute and log stats of packet_in packets
 * \param ctx data context of the module 
 */
int 
destroy(oflops_context *ctx) {
  struct entry *np, *lp;
  double mean, median = -1.0, sd = -1.0;
  size_t i;
  float loss;
  char msg[1024];
  double *data = NULL;
  struct timeval now;

  gettimeofday(&now, NULL);

  if (csv_output.is_open())
      csv_output.close();

  if (head.tqh_first)
    data = (double *) xmalloc(pkt_in_count*sizeof(double));
  i=0;
  for (np = head.tqh_first; np != NULL;) {
    data[i++] = (double)time_diff(&np->snd, &np->rcv);
    lp = np;
    np = np->entries.tqe_next;
    free(lp);
  }

  loss = (double) pkt_in_count/(double)(last_seq - first_seq + 1);
  if(i > 0) {
    gsl_sort (data, 1, i);

    //calculating statistical measures
    mean = gsl_stats_mean(data, 1, i);
    sd = gsl_stats_sd(data, 1, i);
    median = gsl_stats_median_from_sorted_data (data, 1, i);
  } else {
    mean = calculated_mean;
  }
  snprintf(msg, sizeof(msg), "statistics:%f:%f:%f:%f:%zd", (double) mean, median,
      sd, loss, (size_t) pkt_in_count);
  printf("%s\n", msg);
  oflops_log(now, GENERIC_MSG, msg);
  if (ctx->of_version == rofl::openflow13::OFP_VERSION) {
    snprintf(msg, sizeof(msg), "Packets matching the correct cookie= %" PRIu32, pkt_in_cookie_count);
    printf("%s\n", msg);
    oflops_log(now, GENERIC_MSG, msg);
  }

  free(data);
  return 0;
}

/** 
 * \ingroup openflow_packet_in
 * define pcap filters for each channel 
 * \param ctx pointer to opaque context
 * \param ofc channel id
 * \param filter buffer to store filter
 * \param buflen max length of buffer
 */
int 
get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, 
    char * filter, int buflen) {
  // Aminor hack to make the extraction code work
  if (ofc == OFLOPS_DATA1)
    return snprintf(filter, buflen, "udp");
  return 0;
}

/**
 * \ingroup openflow_packet_in
 * log SNMP replies
 * \param ctx data context of module 
 * \param se pointer to SNMP data 
 */
int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int len = 1024, i;
  char msg[1024], log[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);
    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
          (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
        snprintf(log, len, "cpu:%ld:%d:%s",
            se->pdu->reqid, 
            (int)vars->name[ vars->name_length - 1],msg);
        oflops_log(now, SNMP_MSG, log);
      }
    } 

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
          (memcmp(vars->name, ctx->channels[i].inOID,  
                  ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
        snprintf(log, len, "port:rx:%ld:%d:%s",  
            se->pdu->reqid, 
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, log);
        break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
          (memcmp(vars->name, ctx->channels[i].outOID,  
                  ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
        snprintf(log, len, "port:tx:%ld:%d:%s",  
            se->pdu->reqid, 
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, log);
        break;
      }
    } //for
  }
  return 0;
}

/**
 * \ingroup openflow_packet_in
 * Configure packet generator and start packet generation
 * \param ctx data context of the module 
 */
int
handle_traffic_generation (oflops_context *ctx) {
  struct timeval now;
  struct traf_gen_det det;
  struct in_addr ip;
  memset(&ip, 0, sizeof(ip));
  memset(&det, 0, sizeof(det));
  init_traf_gen(ctx);
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"192.168.3.1");
  strcpy(det.dst_ip_max, det.dst_ip_min);
  strcpy(det.mac_src,"00:1e:68:9a:c5:75");
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 0xffff;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = 1000000000/probe_snd_rate;
  strcpy(det.flags, "IPDST_RND");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);

  {
      std::unique_lock<std::mutex> lock(barrier_lock);
      if (!barrier_cond.wait_for(lock, std::chrono::seconds(1), [](){return ready_to_generate;})) {

          oflops_gettimeofday(ctx, &now);
          oflops_log(now, GENERIC_MSG, "Warning barrier message not received within 1 sec. Starting traffic gen anyway");
      }
  }

  //Schedule end
  gettimeofday(&now, NULL);
  add_time(&now, test_duration, 0);
  oflops_schedule_timer_event(ctx, &now, const_cast<char *>(BYESTR));

  start_traffic_generator(ctx);
  return 1;
}

/**
 * \ingroup openflow_packet_in
 * Initialization module with space separated string
 * \param ctx data context of the module 
 * \param config_str initiliazation string
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  //init counters
  gettimeofday(&now, NULL);
  cli_param = strdup(config_str);

  // Strip leading whitespace
  while(*config_str == ' ') config_str++;

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
      else if(strcmp(param, "probe_snd_rate") == 0) {
        //parse int to get measurement probe rate
        probe_snd_rate = strtol(value, NULL, 0);
        if(( probe_snd_rate <= 0))
          perror_and_exit("Invalid probe rate param(Value must be larger than 0)", 1);
      }
      else if(strcmp(param, "print") == 0) {
        print = value;
      }
      else if(strcmp(param, "max_buf_size") == 0) {
        max_buf_size = strtol(value, NULL, 0);
        if (max_buf_size == 0) {
          max_buf_size = rofl::openflow13::OFPCML_NO_BUFFER;
        }
        if (max_buf_size < 58) { // Size of ether+ip+udp+pktgen_hdr
          fprintf(stderr, "max_buf_size must be at least 58 defaulting to that\n");
          max_buf_size = 58;
        }
      }
      else if(strcmp(param, "duration") == 0) {
        test_duration = strtol(value, NULL, 0);
        if (test_duration <= 0)
          perror_and_exit("Invalid duration, value must be larger than 0", 1);
      }
      else if (strcmp(param, "extra_rules") == 0) {
          extra_rules = strtol(value, NULL, 0);
          if (extra_rules < 0)
            perror_and_exit("Invalid number of extra rules, value must be positive", 1);
      }
      else if (strcmp(param, "table") == 0) {
          table_id = strtol(value, NULL, 0);
          if (table_id < 0 or table_id > rofl::openflow13::OFPTT_MAX)
              perror_and_exit("Invalid table id must be less than OFPTT_MAX", 1);
      }
      else {
        fprintf(stderr, "Invalid parameter:%s\n", param);
      }
      param = pos;
    }
  } 

  //calculate sendind interval
  fprintf(stderr, "Sending probe rate : %u usec (pkt_size: %u bytes )\n",
      (uint32_t)probe_snd_rate, (uint32_t)pkt_size);
  return 0;
}
}

int process_packet_in(struct oflops_context *ctx, uint8_t of_version, void *data, size_t len) {
    struct flow fl;
    struct timeval now, then;
    struct pktgen_hdr *pktgen;

    rofl::openflow::cofmsg_packet_in pktin(of_version);
    pktin.set_match().set_version(of_version); // ROFL BUG ? We need to set this, otherwise error
    pktin.unpack((uint8_t *)data, len);

    oflops_gettimeofday(ctx, &now);

    uint8_t * packet = pktin.get_packet().soframe();

    pktgen = extract_pktgen_pkt(ctx, OFLOPS_DATA1, packet,
        ntohs(pktin.get_packet().length()), &fl);

    if(fl.tp_src != 8080) {
      return 0;
    }

    if(pktgen == NULL) {
      //printf("Invalid packet received\n");
      return 0;
    }

    pkt_in_count++;
    if (of_version >= rofl::openflow13::OFP_VERSION &&
            pktin.get_cookie() == MATCH_COOKIE)
        pkt_in_cookie_count++;
    if(first_seq == (uint32_t)-1)
      first_seq = pktgen->seq_num;
    if (last_seq < pktgen->seq_num)
      last_seq = pktgen->seq_num;
    then.tv_sec = pktgen->tv_sec;
    then.tv_usec = pktgen->tv_usec;
    calculated_mean += (time_diff(&then, &now) - calculated_mean) / (pkt_in_count);

    if (csv_output.is_open()) {
        csv_output<<pktgen->tv_sec<<"."<<std::setw(6)<<pktgen->tv_usec
                 <<","<<now.tv_sec<<"."<<std::setw(6)<<now.tv_usec
                 <<","<<pktgen->seq_num<<","<<pktin.get_buffer_id()<<std::endl;
    } else {
        struct entry *n1 = (struct entry *) xmalloc(sizeof(struct entry));
        n1->snd.tv_sec = pktgen->tv_sec;
        n1->snd.tv_usec = pktgen->tv_usec;
        memcpy(&n1->rcv, &now, sizeof(struct timeval));
        n1->id = pktgen->seq_num;
        TAILQ_INSERT_TAIL(&head, n1, entries);
    }

    return 0;
}

static void process_barrier_reply(struct oflops_context *ctx) {
    std::unique_lock<std::mutex> lock(barrier_lock);
    ready_to_generate = true;
    barrier_cond.notify_all();
    struct timeval now;
    oflops_gettimeofday(ctx, &now);
    oflops_log(now, GENERIC_MSG, "Received the barrier reply");
}

#define OF_MESSAGE(version, type) \
    (version == rofl::openflow10::OFP_VERSION ? rofl::openflow10::OFPT_ ##type : \
    version == rofl::openflow12::OFP_VERSION ? rofl::openflow12::OFPT_ ##type : \
    version == rofl::openflow13::OFP_VERSION ? rofl::openflow13::OFPT_ ##type : \
                                               (assert(0), 0) \
    )

extern "C" void of_message (struct oflops_context *ctx, uint8_t of_version, uint8_t type, void *data, size_t len) {
    if (type == OF_MESSAGE(of_version, PACKET_IN)) {
        process_packet_in(ctx, of_version, data, len);
    } else if (type == OF_MESSAGE(of_version, BARRIER_REPLY)) {
        process_barrier_reply(ctx);
    } else {
        struct timeval now;
        char buf[200];
        oflops_gettimeofday(ctx, &now);
        snprintf(buf, sizeof(buf), "Got unexpected OF message %d %s", (int) type, rofl::openflow::cofmsg::type2desc(of_version,type));
        oflops_log(now, GENERIC_MSG, buf);
    }
}
