#include <iostream>
#include <rofl_common.h>
#include <rofl/common/crofbase.h>
#include <rofl/common/openflow/messages/cofmsg.h>
#include <mutex>
#include <deque>

extern "C" {
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <math.h>
#include <limits.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>

#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>

#include "log.h"
#include "traffic_generator.h"
#include "utils.h"
}
#undef OFP_VERSION


/** \defgroup openflow_add_flow openflow add flow
 *   \ingroup modules
 * \brief Openflow flow insertion test module.
 *
 * A module to measure the scalabitily and performance of the flow addition
 * mechanism of an openflow implementation.
 *
 * Parameter:
 *
 * - pkt_size: This parameter can be used to control the length of the
 *   packets in bytes of the measurement probe.
 * - background_rate: The rate of the constant probe, measured in Mbps.
 * - flows:  The number of unique flows that the module will
 *   insert.
 * - reactive - If set packet a stream of packet ins are triggered, with each
 *   installing a rule. Use probe_snd_rate to control the packet in rate.
 * - probe_snd_rate: This parameter controls the data rate of the
 *   measurement probe in packets per second. The default is 1000.
 * - max_buf_size: Set the maximum packet-in size, default no buffer (0)
 * - print: This parameter enables the measurement module to print to the given
 *   file extended per packet measurement information.
 * - duration: The maximum length of the test in seconds, default 60 seconds.
 *   After this period of time the test is stopped, whether or not all flows
 *   have been observed.
 * - table: The ID of the table to put rules into, note only this table is
 *   cleared at the start of the test, allowing goto's in other tables to
 *   persist.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/**
 * \ingroup openflow_add_flow
 * get the name of the module
 * \return name of module
 */
extern "C" const char * name() {
    return "openflow_add_flow";
}

extern "C" const uint8_t *get_openflow_versions() {
    static uint8_t of_versions[] = {0x01, 0x04, 0x0};
    return of_versions;
}

/**
 * event static names
 */
#define BYESTR "bye bye"
#define SND_ACT "send action"
#define SNMPGET "snmp get"

#define BARRIER_START 1
#define BARRIER_FLOWS 2

//logging file
static std::ofstream csv_output;
static std::ofstream csv_pktin;

/**
 * packet size limits
 */
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1500

/**
 * Some constants to help me with conversions
 */
static const uint64_t sec_to_nsec = 1000000000;
static const uint64_t byte_to_bits = 8, mbits_to_bits = 1024*1024;

// packet generation local variables
static int test_duration = 60;
static uint64_t background_rate = 100;
static uint64_t probe_snd_rate = 1000;
static uint32_t pkt_size = 1500;
static const char *network = "192.168.2.0";
static int flows = 100;
static bool reactive = false;
static int table_id = 0;
static uint16_t max_buf_size = rofl::openflow13::OFPCML_NO_BUFFER;
static std::mutex output_lock;
static uint32_t pkt_in_count;
static uint32_t first_seq;
static uint32_t last_seq;
static long double calculated_mean;

//control if a per packet measurement log is created on destroy
static std::string print;
static struct timeval flow_mod_timestamp;

static char *cli_param;

static char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
static char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
    struct timeval snd,rcv;
};
std::deque<struct entry> pktins;

static int *ip_received;
static int ip_received_count;

/**
 * \ingroup openflow_add_flow
 * Initialize mac address of the measurement probe, setup connection
 * channel, insert initial flow set and schedule events.
 * @param ctx pointer to opaque context
 */
extern "C" int
start(struct oflops_context * ctx) {
    int len;
    struct timeval now;
    uint8_t buf[1024];
    char msg[1024];
    rofl::openflow::cofflowmod *fm;

    first_seq = (uint32_t)-1;
    last_seq = 0;
    pkt_in_count = 0;
    calculated_mean = 0;

    pktins.clear();

    bzero(&flow_mod_timestamp, sizeof(struct timeval));
    snprintf(msg, sizeof(msg),  "Intializing module %s", name());
    //log when I start module
    gettimeofday(&now, NULL);
    oflops_log(now, GENERIC_MSG, msg);
    oflops_log(now, GENERIC_MSG, cli_param);
    snprintf(msg, sizeof(msg),  "OpenFlow version %d in use", (int)ctx->of_version);
    oflops_log(now, GENERIC_MSG, msg);
    if (ctx->n_channels < 3) {
        std::cerr<<"Module requires at least 2 data channels"<<std::endl;
        oflops_log(now, GENERIC_MSG, "Module requires at least 2 data channels");
        assert(ctx->n_channels >= 3);
    }

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA2].dev,
            (unsigned char)local_mac[0], (unsigned char)local_mac[1], (unsigned char)local_mac[2],
            (unsigned char)local_mac[3], (unsigned char)local_mac[4], (unsigned char)local_mac[5]);
    get_mac_address(ctx->channels[OFLOPS_DATA2].dev, data_mac);

    //Send a message to clean up flow tables
    rofl::openflow::cofmsg_flow_mod del_flows(ctx->of_version, 1);
    del_flows.set_xid(1);
    fm = &del_flows.set_flowmod();

    fm->set_command(rofl::openflow::OFPFC_DELETE);
    fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
    fm->set_table_id(table_id);
    len = del_flows.length();
    memset(buf, 0, len); // ZERO buffer some devices check padding is zero
    del_flows.pack(buf, 1000);
    oflops_send_of_mesgs(ctx, (char *)buf, len);

    /**
     * Send flow records to start switching packets.
     */
    printf("Sending measurement probe flow...\n");

    // Drop traffic by default, we later add rules to forward it
    rofl::openflow::cofmsg_flow_mod add_flows(ctx->of_version, 1);
    add_flows.set_xid(2);
    fm = &add_flows.set_flowmod();
    fm->set_priority(1000);
    fm->set_command(rofl::openflow::OFPFC_ADD);
    fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
    fm->set_table_id(table_id);
    fm->set_match().set_in_port(ctx->channels[OFLOPS_DATA2].of_port);
    fm->set_match().set_eth_type(ETHERTYPE_IP);

    len = add_flows.length();
    memset(buf, 0, len); // ZERO buffer some devices check padding is zero
    add_flows.pack(buf, 1000);
    oflops_send_of_mesgs(ctx, (char *)buf, len);

    // Packet-ins are sent as packet outs
    add_flows.set_xid(3);
    fm->set_priority(1000);
    fm->set_match().set_in_port(ctx->channels[OFLOPS_DATA1].of_port);
    fm->set_match().set_eth_type(ETHERTYPE_IP);

    rofl::openflow::cofactions &actions2 = ctx->of_version <= rofl::openflow10::OFP_VERSION?
                fm->set_actions():
                fm->set_instructions().set_inst_apply_actions().set_actions();
    rofl::openflow::cofaction_output &output = actions2.add_action_output(rofl::cindex(0));
    output.set_port_no(rofl::openflow::OFPP_CONTROLLER);
    output.set_max_len(max_buf_size);

    len = add_flows.length();
    memset(buf, 0, len); // ZERO buffer some devices check padding is zero
    add_flows.pack(buf, 1000);
    oflops_send_of_mesgs(ctx, (char *)buf, len);

    ip_received = (int *) xmalloc(flows*sizeof(int));
    memset(ip_received, 0, flows*sizeof(int));

    rofl::openflow::cofmsg_barrier_request barrier(ctx->of_version, BARRIER_START);
    len = barrier.length();
    memset(buf, 0, len); // ZERO buffer some devices check padding is zero
    barrier.pack(buf, sizeof(buf));
    oflops_send_of_mesgs(ctx, (char *)buf, len);

    if (!print.empty()) {
      snprintf(msg, sizeof(msg), "Opening output file %s", print.c_str());
      oflops_log(now, GENERIC_MSG, msg);
      csv_output.open(print.c_str());
      csv_output<<std::setfill('0');
      csv_pktin.open((print + ".in").c_str());
      csv_pktin<<std::setfill('0');
    }

    /**
     * Scheduling events
     */
    // create flows after 10 seconds
    if (!reactive) {
        gettimeofday(&now, NULL);
        add_time(&now, 10, 0);
        oflops_schedule_timer_event(ctx,&now, const_cast<char *>(SND_ACT));
    }

    //get port and cpu status from switch
    gettimeofday(&now, NULL);
    add_time(&now, 1, 0);
    oflops_schedule_timer_event(ctx,&now, const_cast<char *>(SNMPGET));

    //end process
    gettimeofday(&now, NULL);
    add_time(&now, test_duration, 0);
    oflops_schedule_timer_event(ctx,&now, const_cast<char *>(BYESTR));

    return 0;
}

/**
 * \ingroup openflow_add_flow
 * Calculate measurement probe stats and output them.
 * \param ctx module context
 */
extern "C" int destroy(struct oflops_context *ctx) {
    double mean, median = -1.0, sd = -1.0;
    size_t i;
    float loss;
    char msg[1024];
    struct timeval now;
    double *data;

    //get what time we start printin output
    gettimeofday(&now, NULL);
    snprintf(msg, sizeof(msg), "Added flows %d received %d", flows, ip_received_count);
    oflops_log(now, GENERIC_MSG, msg);

    if (csv_output.is_open())
        csv_output.close();
    if (csv_pktin.is_open())
        csv_pktin.close();

    if (!pktins.empty())
      data = (double *) xmalloc(pkt_in_count*sizeof(double));
    i=0;
    for (struct entry &pkt : pktins) {
      data[i++] = (double)time_diff(&pkt.snd, &pkt.rcv);
    }
    pktins.clear();

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

    return 0;
}

static inline void add_rule_for_flow(struct oflops_context *ctx, int flow_offset) {
    struct in_addr ip_addr;
    rofl::caddress_in4 addr;
    rofl::openflow::cofmsg_flow_mod add_flows(ctx->of_version, 1);
    rofl::openflow::cofflowmod *fm;
    size_t len;
    static uint8_t buf[1000] = {0};
    struct timeval now;

    // Compute the dst address of the flow
    ip_addr.s_addr = inet_addr(network);
    ip_addr.s_addr = ntohl(ip_addr.s_addr);
    ip_addr.s_addr += flow_offset;
    addr.set_addr_hbo(ip_addr.s_addr);

    // Add a flow to match in channel 2 out 1
    fm = &add_flows.set_flowmod();
    add_flows.set_xid(1000+flow_offset);
    fm->set_priority(1100);
    fm->set_command(rofl::openflow::OFPFC_ADD);
    fm->set_buffer_id(rofl::openflow::OFP_NO_BUFFER);
    fm->set_match().set_in_port(ctx->channels[OFLOPS_DATA2].of_port);
    fm->set_match().set_eth_type(ETHERTYPE_IP);

    rofl::openflow::cofactions &actions = ctx->of_version <= rofl::openflow10::OFP_VERSION?
                fm->set_actions():
                fm->set_instructions().set_inst_apply_actions().set_actions();
    rofl::openflow::cofaction_output &output = actions.add_action_output(rofl::cindex(0));
    output.set_port_no(ctx->channels[OFLOPS_DATA1].of_port);
    output.set_max_len(rofl::openflow13::OFPCML_NO_BUFFER);

    addr.set_addr_hbo(ip_addr.s_addr);
    if (ctx->of_version == rofl::openflow10::OFP_VERSION)
      fm->set_match().set_nw_dst(addr);
    else
      fm->set_match().set_ipv4_dst(addr);

    len = add_flows.length();
    add_flows.pack(buf, sizeof(buf));
    oflops_send_of_mesgs(ctx, (char *)buf, len);
    oflops_gettimeofday(ctx, &now);

    if (flow_offset == 0) {
        oflops_gettimeofday(ctx, &flow_mod_timestamp);
        oflops_log(flow_mod_timestamp, GENERIC_MSG, "START_FLOW_MOD");
    }

    if (csv_output.is_open()) {
        std::lock_guard<std::mutex> lock(output_lock);
        csv_output<<"ADDING_FLOW,"<<now.tv_sec<<"."<<std::setw(6)<<now.tv_usec
                 <<","<<flow_offset<<std::endl;
    }

    // The final flow send a barrier
    if (flow_offset+1 == flows) {
        rofl::openflow::cofmsg_barrier_request barrier(ctx->of_version, BARRIER_FLOWS);
        len = barrier.length();
        memset(buf, 0, len); // ZERO buffer some devices check padding is zero
        barrier.pack(buf, sizeof(buf));
        oflops_send_of_mesgs(ctx, (char *)buf, len);
        oflops_gettimeofday(ctx, &now);
        if (csv_output.is_open()) {
            std::lock_guard<std::mutex> lock(output_lock);
            csv_output<<"BARRIER_REQUEST,"<<now.tv_sec<<"."<<std::setw(6)
                     <<now.tv_usec<<std::endl;
        }
    }
}

/**
 * \ingroup openflow_add_flow
 * Handle timer event.
 * - BYESTR: terminate module execution
 * - SND_ACT: send new flows to switch
 * - SNMPGET: query stats from switch using snmp
 * @param ctx context of module
 * @param te event data
 */
extern "C" int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {
    char *str = (char *) te->arg;
    int i;

    //terminate process
    if (strcmp(str, BYESTR) == 0) {
        printf("terminating test....\n");
        oflops_end_test(ctx,1);
        return 0;
    } else if (strcmp(str, SND_ACT) == 0) {

        oflops_gettimeofday(ctx, &flow_mod_timestamp);
        oflops_log(flow_mod_timestamp, GENERIC_MSG, "START_FLOW_MOD");

        // create new rules
        for(i=0; i < flows; i++) {
            add_rule_for_flow(ctx, i);
        }

        oflops_gettimeofday(ctx, &flow_mod_timestamp);
        oflops_log(flow_mod_timestamp, GENERIC_MSG, "END_FLOW_MOD");
        printf("sending flow modifications ....\n");

    } else if(strcmp(str, SNMPGET) == 0) {
        /*for(i = 0; i < ctx->cpuOID_count; i++) {*/
            /*oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);*/
        /*}*/
        /*for(i=0;i<ctx->n_channels;i++) {*/
            /*oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);*/
            /*oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);*/
        /*}*/
        /*gettimeofday(&now, NULL);*/
        /*add_time(&now, 120, 0);*/
        /*oflops_schedule_timer_event(ctx,&now, SNMPGET);*/
    }
    return 0;
}

/**
 * \ingroup openflow_add_flow
 * Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap * @param buflen length of buffer
 */
extern "C" int
get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc,
        char * filter, int buflen) {
    if (ofc == OFLOPS_CONTROL) {
        return 0;
    } else if ((ofc == OFLOPS_DATA1)) {
        return snprintf(filter, buflen, "udp");
    }
    return 0;
}

/**
 * \ingroup openflow_add_flow
 * Handle event on data plane
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
extern "C" int
handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch) {
    struct pktgen_hdr *pktgen;
    struct flow fl;
    struct timeval now;
    char msg[1024];
    struct in_addr in;

    if ((ch == OFLOPS_DATA1)) {
        if((pktgen = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, pe->pcaphdr.caplen, &fl)) == NULL) {
            printf("Failed to parse packet\n");
            return 0;
        }

        if ((flow_mod_timestamp.tv_sec > 0) &&  (ch == OFLOPS_DATA1)) {
            int id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
            if ((id >= 0) && (id < flows) && (!ip_received[id])) {
                ip_received_count++;
                ip_received[id] = 1;
                in.s_addr = fl.nw_dst;
                snprintf(msg, 1024, "FLOW_INSERTED:%s", inet_ntoa(in));
                oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
                if (csv_output.is_open()) {
                    std::lock_guard<std::mutex> lock(output_lock);
                    csv_output<<"RECEIVED_FLOW,"<<pe->pcaphdr.ts.tv_sec<<"."<<std::setw(6)
                             <<pe->pcaphdr.ts.tv_usec<<","<<id<<std::endl;
                }
                if (ip_received_count >= flows) {
                    printf("Received all packets to channel 2\n");
                    snprintf(msg, 1024, "COMPLETE_INSERT_DELAY:%u", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
                    printf("%s\n", msg);
                    oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
                    oflops_log(pe->pcaphdr.ts, GENERIC_MSG, "LAST_PKT_RCV");
                    gettimeofday(&now, NULL);
                    add_time(&now, 0, 10);
                    oflops_schedule_timer_event(ctx,&now, const_cast<char *>(SNMPGET));
                    add_time(&now, 10, 0);
                    oflops_schedule_timer_event(ctx,&now, const_cast<char *>(BYESTR));
                }
            }
        }
    }
    return 0;
}

/**
 * \ingroup openflow_add_flow
 * log information from snmp replies
 * \param ctx data of the context of the module
 * \param se the snmp reply of the message
 */
extern "C" int
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
                        (int)vars->name[ vars->name_length - 1], msg);
                oflops_log(now, SNMP_MSG, log);
            }
        }

        for(i=0;i<ctx->n_channels;i++) {
            if((vars->name_length == ctx->channels[i].inOID_len) &&
                    (memcmp(vars->name, ctx->channels[i].inOID,
                            ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
                snprintf(log, len, "port:rx:%ld:%d:%d",
                        se->pdu->reqid,
                        (int)(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], (uint32_t)*(vars->val.integer));
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
    }// if cpu
    return 0;
}


/**
 * \ingroup openflow_add_flow
 * start generation of 2 measrument probe(constant and variable)
 * \param ctx data of the context of the module.
 */
extern "C" int
handle_traffic_generation (oflops_context *ctx) {
    struct traf_gen_det det;
    struct in_addr ip_addr;
    const int bg_pktsize = 64;
    uint64_t bg_snd_interval;

    //calculate sendind interval
    bg_snd_interval = (bg_pktsize * byte_to_bits * sec_to_nsec) / (background_rate * mbits_to_bits);
    fprintf(stderr, "Sending probe interval : %f usec (%f usec) (pkt_size: %u bytes, rate: %u Mbits/sec)\n",
            bg_snd_interval/1000.0, bg_snd_interval/1000.0*flows,(uint32_t)bg_pktsize, (uint32_t)background_rate);

    init_traf_gen(ctx);

    //background data
    strcpy(det.src_ip, "10.1.1.1");
    strcpy(det.dst_ip_min, network);

    ip_addr.s_addr = ntohl(inet_addr(network));
    ip_addr.s_addr += (flows-1);
    ip_addr.s_addr = htonl(ip_addr.s_addr);
    strcpy(det.dst_ip_max, inet_ntoa(ip_addr));
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00"); //"00:1e:68:9a:c5:74");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)data_mac[0], (unsigned char)data_mac[1],
                (unsigned char)data_mac[2], (unsigned char)data_mac[3],
                (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

    strcpy(det.mac_dst,"00:15:17:7b:92:0a");
    det.vlan = 0xffff;
    det.vlan_p = 0;
    det.vlan_cfi = 0;
    det.udp_src_port = 8080;
    det.udp_dst_port = 8080;
    det.pkt_size = bg_pktsize;
    det.delay = bg_snd_interval;
    strcpy(det.flags, "");
    add_traffic_generator(ctx, OFLOPS_DATA2, &det);

    if (reactive) {
        det.pkt_size = pkt_size;
        strcpy(det.src_ip, "10.1.1.1");
        strcpy(det.dst_ip_min, "10.1.1.1");
        strcpy(det.dst_ip_max, "10.1.1.1");
        det.delay = 1000000000 / probe_snd_rate;
        add_traffic_generator(ctx, OFLOPS_DATA1, &det);
    }

    sleep(1);

    start_traffic_generator(ctx);
    return 1;
}

/**
 * \ingroup openflow_add_flow
 * Initialization code of the module parameter.
 * \param ctx data of the context of the module.
 * \param config_str the initiliazation string of the module.
 */
extern "C" int init(struct oflops_context *ctx, char * config_str) {
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
            } else if(strcmp(param, "background_rate") == 0) {
                //parse int to get measurement probe rate
                background_rate = strtol(value, NULL, 0);
                if((background_rate <= 0) || (background_rate >= 10010))
                    perror_and_exit("Invalid data rate param(Value between 1 and 10010)", 1);
            } else if(strcmp(param, "probe_snd_rate") == 0) {
                //parse int to get measurement probe rate
                probe_snd_rate = strtol(value, NULL, 0);
                if((probe_snd_rate <= 0))
                    perror_and_exit("Invalid probe rate param(Value must be larger than 0)", 1);
            } else if(strcmp(param, "flows") == 0) {
                //parse int to get pkt size
                flows = strtol(value, NULL, 0);
                if(flows <= 0)
                    perror_and_exit("Invalid flow number", 1);
            } else if(strcmp(param, "print") == 0) {
                print = value;
            } else if(strcmp(param, "duration") == 0) {
                test_duration = strtol(value, NULL, 0);
                if (test_duration <= 0)
                    perror_and_exit("Invalid duration, value must be larger than 0", 1);
            } else if(strcmp(param, "reactive") == 0) {
                reactive = strtol(value, NULL, 0);
            } else if(strcmp(param, "max_buf_size") == 0) {
                max_buf_size = strtol(value, NULL, 0);
                if (max_buf_size == 0) {
                    max_buf_size = rofl::openflow13::OFPCML_NO_BUFFER;
                }
                if (max_buf_size < 58) { // Size of ether+ip+udp+pktgen_hdr
                    fprintf(stderr, "max_buf_size must be at least 58 defaulting to that\n");
                    max_buf_size = 58;
                }
            }
            else if (strcmp(param, "table") == 0) {
                table_id = strtol(value, NULL, 0);
                if (table_id < 0 || table_id > rofl::openflow13::OFPTT_MAX)
                    perror_and_exit("Invalid table id must be less than OFPTT_MAX", 1);
            } else
                fprintf(stderr, "Invalid parameter:%s\n", param);
            param = pos;
        }
    }
    return 0;
}


static void process_packet_in(struct oflops_context *ctx, uint8_t of_version,
                       void *data, size_t len) {
    static int flow_num = 0;
    struct flow fl;
    struct timeval now, then;
    struct pktgen_hdr *pktgen;

    if (flow_num < flows)
    {
        add_rule_for_flow(ctx, flow_num);
        flow_num++;
    }

    rofl::openflow::cofmsg_packet_in pktin(of_version);
    pktin.set_match().set_version(of_version); // ROFL BUG ? We need to set this, otherwise error
    pktin.unpack((uint8_t *)data, len);

    oflops_gettimeofday(ctx, &now);
    uint8_t * packet = pktin.get_packet().soframe();

    pktgen = extract_pktgen_pkt(ctx, OFLOPS_DATA1, packet,
        ntohs(pktin.get_packet().length()), &fl);

    if(fl.tp_src != 8080) {
      return;
    }

    if(pktgen == NULL) {
      //printf("Invalid packet received\n");
      return;
    }

    pkt_in_count++;
    if(first_seq == (uint32_t)-1)
      first_seq = pktgen->seq_num;
    if (last_seq < pktgen->seq_num)
      last_seq = pktgen->seq_num;
    then.tv_sec = pktgen->tv_sec;
    then.tv_usec = pktgen->tv_usec;
    calculated_mean += (time_diff(&then, &now) - calculated_mean) / (pkt_in_count);

    if (csv_pktin.is_open()) {
        csv_pktin<<"PACKET_IN,"<<pktgen->tv_sec<<"."<<std::setw(6)<<pktgen->tv_usec
                 <<","<<now.tv_sec<<"."<<std::setw(6)<<now.tv_usec
                 <<","<<pktgen->seq_num<<","<<pktin.get_buffer_id()<<std::endl;
    } else {
        struct entry n1;
        n1.snd.tv_sec = pktgen->tv_sec;
        n1.snd.tv_usec = pktgen->tv_usec;
        memcpy(&n1.rcv, &now, sizeof(struct timeval));
        pktins.push_back(n1);
    }

}

static void process_barrier(struct oflops_context *ctx, uint8_t of_version,
                            void *data, size_t len) {

    rofl::openflow::cofmsg_barrier_reply b_reply(of_version);
    b_reply.unpack((uint8_t *)data, len);
    if (b_reply.get_xid() == BARRIER_FLOWS) {
        struct timeval now;
        oflops_gettimeofday(ctx, &now);
        oflops_log(now, GENERIC_MSG, "BARRIER_REPLY");
        std::lock_guard<std::mutex> lock(output_lock);
        if (csv_output.is_open()) {
            csv_output<<"BARRIER_REPLY,"<<now.tv_sec<<"."<<std::setw(6)<<now.tv_usec<<std::endl;
        }
    }
    if (b_reply.get_xid() == BARRIER_START) {
        struct timeval now;
        oflops_gettimeofday(ctx, &now);
        oflops_log(now, GENERIC_MSG, "BARRIER_START");
        std::lock_guard<std::mutex> lock(output_lock);
        if (csv_output.is_open()) {
            csv_output<<"BARRIER_START,"<<now.tv_sec<<"."<<std::setw(6)<<now.tv_usec<<std::endl;
        }
    }
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
        process_barrier(ctx, of_version, data, len);
    } else {
        struct timeval now;
        char buf[200];
        oflops_gettimeofday(ctx, &now);
        snprintf(buf, sizeof(buf), "Got unexpected OF message %d %s", (int) type, rofl::openflow::cofmsg::type2desc(of_version,type));
        oflops_log(now, GENERIC_MSG, buf);
    }
}
