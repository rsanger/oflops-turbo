#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <math.h>

//include gsl to implement statistical functionalities
#include <gsl/gsl_statistics.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"

#ifndef BUFLEN
#define BUFLEN 4096
#endif

/** String for scheduling events
 */
#define BYESTR "bye bye"
#define GETSTAT "getstat"
#define SNMPGET "snmp get"

/** packet size constants
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

#define TEST_DURATION 30

#define MIN_QUERY_DELAY 1000

#define SEC_TO_USEC 1000000

#define LOG_FILE "measure.log"

/*
 * Number of flow rules we send to the switch
 */
int flows = 128;
int flows_exponent, query_exponent;
int query = 64;
int query_delay = 1000000; //1 sec
char *network = "192.168.2.0";

/** Some constants to help me with conversions
 */
const uint64_t sec_to_usec = 1000000;
const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

/** The rate at which data will be send between the data ports (In Mbits per sec.). 
 */
uint64_t datarate = 100;
uint64_t proberate = 100;

/** pkt sizes. 
 */
uint64_t pkt_size = 1500;

// variable to store the state of the process
int finished; 
int poll_started = 0;

/*
 * calculated sending time interval (measured in usec). 
 */
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

struct timeval stats_start;
int trans_id=0;

char *logfile = LOG_FILE;

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  uint32_t nw_dst;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
}; 
TAILQ_HEAD(tailhead, entry) head;

struct stats_entry {
  struct timeval rcv,snd;
  int pkt_count;
} stats_counter[(TEST_DURATION * SEC_TO_USEC)/MIN_QUERY_DELAY];

int stats_count = 0;

// control whether detailed packet information is printed
int print = 0, table = 0;
int count[] = {0,0,0}; // counting how many packets where received over a 
// specific channel
//the local mac address of the probe 
char probe_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

/**
 * \defgroup openflow_flow_stats openflow flow stats
 * \ingroup modules
 * The module benchmark the performance of the implementation of the openflow flow
 * statistics mechanism
 * 
 * Parameters: 
 * 
 *  - flows}: The total number of unique flow that the module will
 * initialize the flow table of the switch. (default 128)
 *  - query}: The number of unique flows that the module will query the 
 *   switch in each flow request. Because the matching method of the module is based 
 * on the netmask field of the matching field. (default 128)
 *  - pkt\_size}:  This parameter can be used to control the length of the
 *   packets of the measurement probe. It allows indirectly to adjust the packet
 *   throughput of the experiment.
 *  - data\_rate}: The rate, in Mbps, of the variable probe. (default
 *       10Mbps)
 *  - probe\_rate}: The rate, in Mbps, of the constant probe. (default 10Mbps)
 *  - query\_delay}: The delay, in microseconds, between the different 
 * stats requests. (default 10000 usec) 
 *  - print}: A parameter that defines whether the module will output full
 *   per packet details of the measurement probes. If this value is set to 1, then
 *   the module will print on a file called "measure.log" for each capture packet a
 *   comma separated record with the timestamps of the generation and capture times of the
 *   packet, the packet id, the port at which the packet was captured and the flow id 
 * of the flow that was used in order to switch the packet. (default 0)
 *  - table}: This parameter controls whether the inserted flow will be
 * a wildcard(value of 1) or exact match(value of 0). (default 0)
 * 
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 */

/**
 * \ingroup openflow_flow_stats
 * get module name
 * @return name of module
 */
char * name()
{
  return "openflow_flow_dump_test";
}

/**
 * \ingroup openflow_flow_stats
 * configure module parameters
 * \param ctx data context of the module
 * \param config_str a space separated initilization string
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  double exponent;

  printf("log initialized\n");

  //init measurement queue
  TAILQ_INIT(&head); 

  while(*config_str == ' ') {
    config_str++;
  }
  param = config_str;
  while(1) {
    pos = index(param, ' ');

    if((pos == NULL)) {
      if (*param != '\0') {
        pos = param + strlen(param) + 1;
      } else
        break;
    }
    *pos='\0';
    pos++;
    value = index(param,'=');
    *value = '\0';
    value++;
    if(value != NULL) {
      if(strcmp(param, "flows") == 0) {
        flows = atoi(value);
        if(flows <= 0)
          perror_and_exit("Invalid flow number",1);
      } else if(strcmp(param, "query") == 0) {
        //define the number of flows queried in each turn
        query = atoi(value);
        if(query <= 0)
          perror_and_exit("Invalid flow number",1);
        exponent = log2(query);
        if(exponent - floor(exponent) != 0) {
          query = (int)pow(2, ceil(exponent));
          printf("query size must be a power of 2. converting to %d\n", query);
        }
      } else if(strcmp(param, "network") == 0) {
        //network range to send data for the data probe
        network = (char *)xmalloc(strlen(value) + 1);
        strcpy(network, value);
      } else if(strcmp(param, "pkt_size") == 0) {
        //packet size for the probes
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))  {
          perror_and_exit("Invalid packet size value", 1);
        }
      } else if(strcmp(param, "data_rate") == 0) {
        //multituple data rate
        datarate = strtol(value, NULL, 0);
        if((datarate <= 0) || (datarate > 1010))  {
          perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
        }

      } else if(strcmp(param, "probe_rate") == 0) {
        //single tuple data rate
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) {
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
        }

        //time gap between querries in usec
      } else if(strcmp(param, "query_delay") == 0) {
        query_delay = strtol(value, NULL, 0);
        if(query_delay <= MIN_QUERY_DELAY) {
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
        }
        printf("query delay %d\n", query_delay);
        //should packet timestamp be printed
      } else if(strcmp(param, "print") == 0) {
        //parse int to get pkt size
        print = strtol(value, NULL, 0);
      }else if(strcmp(param, "table") == 0) {
        //parse int to get pkt size
        table = strtol(value, NULL, 0);
      } else {
        fprintf(stderr, "Invalid parameter:%s\n", param);
      }
      param = pos;
    }
  } 

  //calculating interpacket gap
  data_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (datarate * mbits_to_bits);
  fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  probe_snd_interval = (pkt_size * byte_to_bits * sec_to_usec) / (proberate * mbits_to_bits);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n", 
      (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);
  fprintf(stderr, "sending %d flows, quering %d flows every %u usec\n", 
      flows, query, query_delay);


  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * calculate the statistics of the measurement probe and the statistic reply
 * \param ctx data context of the module 
 */
int destroy(struct oflops_context *ctx) {
  char msg[1024];
  struct timeval now;
  FILE *out = fopen(logfile, "w");
  struct entry *np;
  uint32_t mean, median, std;
  int min_id[] = {INT_MAX, INT_MAX, INT_MAX}; 
  int max_id[] = {INT_MIN, INT_MIN, INT_MIN};
  int ix[] = {0, 0, 0};
  int ch, i;
  float loss;
  double **data;
  struct in_addr in;

  gettimeofday(&now, NULL);
  fprintf(stderr, "This is the destroy code of the module\n");

  data = (double **)malloc(3*sizeof(double*));
  for(ch = 0; ch < 3; ch++) 
    if(count[ch])
      data[ch] = (double *)malloc(count[ch] * sizeof(double));
    else
      data[ch] = NULL;

  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    if((np->ch > OFLOPS_DATA3) || ((np->ch < OFLOPS_DATA1))){ 
      printf("Invalid channel %d. skipping packet\n", np->ch);
      continue;
    }
    ch = np->ch - 1;
    if(print) {
      in.s_addr = np->nw_dst;
      if(fprintf(out, "%lu %lu.%06lu %lu.%06lu %d %s\n", 
            (long unsigned int)np->id,  
            (long unsigned int)np->snd.tv_sec, 
            (long unsigned int)np->snd.tv_usec,
            (long unsigned int)np->rcv.tv_sec, 
            (long unsigned int)np->rcv.tv_usec,  
            np->ch, inet_ntoa(in)) < 0)  
        perror_and_exit("fprintf fail", 1); 
    }
    if( time_cmp(&np->snd, &np->rcv)> 0) {
      ix[ch]++; 
      min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
      max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
      data[ch][ix[ch]] = (double) time_diff(&np->snd, &np->rcv);
    }
    free(np);
  }

  for(ch = 0; ch < 3; ch++) {
    if(ix[ch] == 0) continue;
    gsl_sort (data[ch], 1, ix[ch]);
    mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
    std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
    loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);
    snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d", 
        ch, mean, median, std, loss, ix[ch]);
    printf("%s\n", msg);
    oflops_log(now, GENERIC_MSG, msg);

  }

  ix[0] = 0;
  if(data[0] != NULL)
    free(data[0]);
  data[0] = (double *)malloc(sizeof(double)*(stats_count));

  for (i = 0; i < trans_id; i++) {
    if(((stats_counter[i].rcv.tv_sec == 0) && 
          (stats_counter[i].rcv.tv_usec == 0)) || 
        (ix[0] >=  stats_count)) continue;
    data[0][ix[0] - 1]  = (double) time_diff(&stats_counter[i].snd, &stats_counter[i].rcv);
    ix[0]++;
    snprintf(msg, 1024, "stats:%u:%d:%u.%06u:%u.%06u:%u",i,  
        stats_counter[i].pkt_count,  
        stats_counter[i].snd.tv_sec, 
        stats_counter[i].snd.tv_usec,
        stats_counter[i].rcv.tv_sec, 
        stats_counter[i].rcv.tv_usec,
        time_diff(&stats_counter[i].snd,  
          &stats_counter[i].rcv));
    printf("%s\n", msg);
    oflops_log(now, GENERIC_MSG, msg);
    //free(stats_np);
  }

  if(ix[0] > 0) {
    gsl_sort (data[0], 1, ix[0]);
    mean = (uint32_t)gsl_stats_mean(data[0], 1, ix[0]);
    std = (uint32_t)sqrt(gsl_stats_variance(data[0], 1, ix[0]));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data[0], 1, ix[0]);
    loss = (float)ix[0]/(float)(max_id[0] - min_id[0]);
    snprintf(msg, 1024, "statistics:stats:%u:%u:%u:%.04f:%d", 
        mean, median, std, loss, ix[0]);
    printf("%s\n", msg);
    oflops_log(now, GENERIC_MSG, msg);
  } else {
    oflops_log(now, GENERIC_MSG, "stats_stats:fail");
  }
  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * the module initiliazes internal state of the module, inserts appropriate flows in flows
 * table and schedules appropriate events. 
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx)
{
  int res = -1, i, len = 0;
  struct timeval now;
  struct pollfd * poll_set = malloc(sizeof(struct pollfd));
  struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
  int ret = 0;

  // a genric structure with which 
  // we can create and send messages. 
  void *b;

  //make filedescriptor blocking
  /*int saved_flags = fcntl(ctx->control_fd, F_GETFL);
  fcntl(ctx->control_fd, F_SETFL, saved_flags & ~O_NONBLOCK);*/

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);
  get_mac_address(ctx->channels[OFLOPS_DATA2].dev, probe_mac);

  gettimeofday(&now, NULL);
  oflops_log(now,GENERIC_MSG , "Intializing module openflow_flow_dump_test");

  make_ofp_hello(&b);
  res = oflops_send_of_mesg(ctx, b);
  free(b);  

  // send a delete all message to clean up flow table.
  make_ofp_feat_req(&b);
  res = oflops_send_of_mesg(ctx, b);
  free(b);

  // send a features request, to stave off timeout (ignore response)
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  res = oflops_send_of_mesg(ctx, b);
  free(b);

  //Send a singe ruke to route the traffic we will generate
  bzero(fl, sizeof(struct flow));
  if (table) 
    fl->mask =  OFPFW_IN_PORT | OFPFW_DL_DST | OFPFW_DL_SRC | 
      (0 << OFPFW_NW_SRC_SHIFT) | (0 << OFPFW_NW_DST_SHIFT) | 
      OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO | 
      OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;
  else
    fl->mask = 0;
  fl->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port); 
  fl->dl_type = htons(ETHERTYPE_IP); 
  memcpy(fl->dl_src, probe_mac, ETH_ALEN); 
  memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN); 
  fl->dl_vlan = 0xffff;
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst =  inet_addr("10.1.1.2");
  fl->tp_src = htons(8080);            
  fl->tp_dst = htons(8080);  
  len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA3].of_port, 1, 1200);
  res = oflops_send_of_mesg(ctx, b);
  free(b);

  printf("Sending new flow rules...\n");
  fl->nw_dst = inet_addr(network);
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  fl->dl_vlan = 0xffff; 
  memcpy(fl->dl_src, data_mac, ETH_ALEN); 
  memcpy(fl->dl_dst, "\x00\x1e\x68\x9a\xc5\x75", ETH_ALEN); 
  fl->mask = 0; 
  for(i=0; i< flows; i++) {
//    do {
//      bzero(poll_set, sizeof(struct pollfd));
//      poll_set[0].fd = ctx->control_fd;
//      poll_set[0].events = POLLOUT;
//      ret = poll(poll_set, 1, -1);
//    } while ((ret == 0) || ((ret > 0) && !(poll_set[0].revents & POLLOUT)) );
//
//    if(( ret == -1 ) && ( errno != EINTR))
//      perror_and_exit("poll",1);

    len = make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 1, 1200);
    res = oflops_send_of_mesg(ctx, b);
    free(b);

    //calculate next ip
    fl->nw_dst =  htonl(ntohl(fl->nw_dst) + 1);
  }

  //Schedule end
  gettimeofday(&now, NULL);
  add_time(&now, TEST_DURATION, 0);
  oflops_schedule_timer_event(ctx,&now, BYESTR);

  //the event to request the flow statistics. 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, GETSTAT);

  //get port and cpu status from switch 
  gettimeofday(&now, NULL);
  add_time(&now, 1, 0);
  oflops_schedule_timer_event(ctx,&now, SNMPGET);

  flows_exponent = (int)floor(log2(flows));
  query_exponent = (int)log2(query);

  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * Handle timer event: 
 * - GETSTAT: send sta request
 * - SNMPGET: send SNMP request
 * - BYESTR: terminate module
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te)
{
  int res = -1, len, i;
  void *b = NULL;
  char *str = te->arg;
  struct timeval now;
  char msg[100];
  uint32_t flow_netmask;
  struct ofp_flow_stats_request *reqp;
  //send flow statistics request. 
  if(strcmp(str, GETSTAT) == 0) {
    //sprintf(msg, "%d", trans_id);

    //log start of measurement
    if(trans_id == 0) {
      printf("flow stats request send with xid %s\n", msg);  
      memcpy(&stats_start, &te->sched_time, sizeof(struct timeval));
      poll_started = 1;
    }
    memcpy(&stats_counter[trans_id].snd, &te->sched_time, sizeof(struct timeval));
    bzero(&stats_counter[trans_id].rcv, sizeof(struct timeval));
    //create generic statrequest message
    len = make_ofp_flow_get_stat(&b, trans_id++);
    reqp = (struct ofp_flow_stats_request *)(b + sizeof(struct ofp_stats_request));

    //set the query mask
    reqp->match.wildcards = htonl(OFPFW_IN_PORT |  OFPFW_DL_VLAN |  OFPFW_DL_SRC |
        OFPFW_DL_DST |  OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC |
        OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS | OFPFW_TP_DST |
        (32 << OFPFW_NW_SRC_SHIFT) | ((query_exponent) << OFPFW_NW_DST_SHIFT));

    //calculate netowrk mask for the query
    flow_netmask = (ntohl(inet_addr(network)) & ((0xFFFFFFFF)<<flows_exponent));
    if(query_exponent < flows_exponent) 
      flow_netmask += (stats_count%(0x1 <<(flows_exponent-query_exponent)) 
          << query_exponent);

    reqp->match.nw_dst = htonl(flow_netmask);

    //send stats request
    res = oflops_send_of_mesg(ctx, b);
    free(b);

    //schedule next query
    gettimeofday(&now, NULL);
    add_time(&now, query_delay/SEC_TO_USEC, query_delay%SEC_TO_USEC);
    oflops_schedule_timer_event(ctx, &now, GETSTAT);
  } else if (strcmp(str, BYESTR) == 0) {
    //terminate programm execution
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
  } else if(strcmp(str, SNMPGET) == 0) {
    for(i=0;i<ctx->cpuOID_count;i++) 
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);

    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }  
    gettimeofday(&now, NULL);
    add_time(&now, 10, 0);
    oflops_schedule_timer_event(ctx,&now, SNMPGET);
  }
  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * handle SMMP asynchronous  replies
 * \param ctx data context of the module 
 * \param se snmp reply data
 */
int 
handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int i, len = 1024;
  char msg[1024], count[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {    
    snprint_value(msg, len, vars->name, vars->name_length, vars);

    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
          (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
        snprintf(count, len, "cpu : %s %%", msg);
        oflops_log(now, SNMP_MSG, count);
      }
    }

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
          (memcmp(vars->name, ctx->channels[i].inOID,  
                  ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
        snprintf(count, len, "port %d : rx %s pkts",  
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], 
            msg);
        oflops_log(now, SNMP_MSG, count);
        break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
          (memcmp(vars->name, ctx->channels[i].outOID,  
                  ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
        snprintf(count, len, "port %d : tx %s pkts",  
            (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
        oflops_log(now, SNMP_MSG, count);
        break;
      }
    } //for
  }// if cpu
  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc channel ID 
 * @param filter return buffer for the filter
 * @param buflen length of buffer
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
  if(ofc == OFLOPS_CONTROL) {
    return 0;
    return snprintf(filter,buflen,"port %d", ctx->listen_port);
  } else if ( (ofc == OFLOPS_DATA3) || (ofc == OFLOPS_DATA2)) {
    return snprintf(filter,buflen,"udp");
    return 0;
  }
  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * Handle pcap event on data channels only
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event *pe,
    oflops_channel_name ch) {
  struct pktgen_hdr *pktgen;
  struct flow fl;

  if ((ch == OFLOPS_DATA3) || (ch == OFLOPS_DATA2)) {
    if(!poll_started) return 0;
    pktgen = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, pe->pcaphdr.caplen, &fl);
    if(pktgen == NULL) { //skip non IP packets
      printf("failed to parse header\n");
      return 0;
    }
    struct entry *n1 = xmalloc(sizeof(struct entry));
    n1->snd.tv_sec = pktgen->tv_sec;
    n1->snd.tv_usec = pktgen->tv_usec;
    memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
    n1->id = pktgen->seq_num;
    n1->ch = ch;
    n1->nw_dst = fl.nw_dst;
    count[ch - 1]++;
    TAILQ_INSERT_TAIL(&head, n1, entries);
  }
  return 0;
}

/**
 * \ingroup openflow_flow_stats
 * generate traffic on data plane 
 * \param ctx data context of the module.
 */
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  char *str_ip;
  struct in_addr ip;
  init_traf_gen(ctx);

  //background data
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"192.168.2.0");

  ip.s_addr = ntohl(inet_addr("192.168.2.0"));
  ip.s_addr += (flows - 1);
  ip.s_addr = htonl(ip.s_addr);
  str_ip = inet_ntoa(ip);
  strcpy(det.dst_ip_max, str_ip);
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00");
  else 
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)data_mac[0], (unsigned char)data_mac[1], 
        (unsigned char)data_mac[2], (unsigned char)data_mac[3], 
        (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

  strcpy(det.mac_dst,"00:1e:68:9a:c5:75");
  det.vlan = 0xffff;
  det.vlan_p = 1;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval*1000;
  strcpy(det.flags, "IPDST_RND");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);
  //measurement probe
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00"); 
  else 
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)probe_mac[0], (unsigned char)probe_mac[1], 
        (unsigned char)probe_mac[2], (unsigned char)probe_mac[3], 
        (unsigned char)probe_mac[4], (unsigned char)probe_mac[5]);
  strcpy(det.mac_dst,"00:15:17:7b:92:0a");
  det.vlan = 0xffff;
  det.delay = probe_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA2, &det);
  start_traffic_generator(ctx);
  return 1;
}

/**
 * \ingroup openflow_flow_stats
 * handle openflow stats reply and openflow errors
 * \param ctx data context of the module 
 * \param ofph pointer to the data of the packet 
 */
int
of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph) {
  struct timeval now;
  char msg[100];
  struct ofp_error_msg *err_p;

  if(ofph->type == OFPT_STATS_REPLY) {
    struct ofp_stats_reply *ofpr = (struct ofp_stats_reply *)ofph;
    stats_counter[ntohl(ofph->xid)].pkt_count++;
    if(ntohs(ofpr->type) == OFPST_FLOW) {
      if(!(ntohs(ofpr->flags) & OFPSF_REPLY_MORE)) {
        gettimeofday(&now, NULL);
        memcpy(&stats_counter[ntohl(ofph->xid)].rcv, &now, sizeof(struct timeval));
        stats_count++;
      }
    }
  } else if (ofph->type == OFPT_ERROR) {
    err_p = (struct ofp_error_msg *)ofph;
    sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
    fprintf(stderr, "%s\n", msg);
    perror_and_exit(msg, 1);
  }
  return 0;
}
