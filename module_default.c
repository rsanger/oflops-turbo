#include <string.h>

#include "module_default.h"
#include "pcap_track.h"

// Set of default operations for modules; just NOOPs except for OFLOPS_CONTROL which we keep timestamps for

int default_module_init(struct oflops_context *ctx, char * init)
{
    return 0;
}


int default_module_destroy(struct oflops_context *ctx)
{
    return 0;
}

int default_module_get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
    return 0;
}


int default_module_start(struct oflops_context * ctx) {
    return 0;
}


int default_module_handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch)
{
    return 0;
    if( ch != OFLOPS_CONTROL)
        return 0;
    if(!ctx->channels[OFLOPS_CONTROL].timestamps)
        ctx->channels[OFLOPS_CONTROL].timestamps = ptrack_new();
    // add this packet to the list of timestamps
    return ptrack_add_of_entry(ctx->channels[OFLOPS_CONTROL].timestamps, pe->data, pe->pcaphdr.caplen, pe->pcaphdr);
}



int default_module_of_event_packet_in(struct oflops_context *ctx, const struct ofp_packet_in * pktin)
{
    return 0;
}



#ifdef HAVE_OFP_FLOW_EXPIRED
int default_module_of_event_flow_removed(struct oflops_context *ctx, const struct ofp_flow_expired * ofph)
#elif defined(HAVE_OFP_FLOW_REMOVED)
int default_module_of_event_flow_removed(struct oflops_context *ctx, const struct ofp_flow_removed * ofph)
#else
#error "Unknown version of openflow"
#endif
{
    return 0;
}

int default_module_of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph)
{
    struct ofp_header resp;
    memcpy(&resp,ofph,sizeof(resp));
    resp.type = OFPT_ECHO_REPLY;
    oflops_send_of_mesg(ctx, &resp);
    return 0;
}


int default_module_of_event_port_status(struct oflops_context * ctx, const struct ofp_port_status * ofph)
{
    return 0;
}
int default_module_of_event_other(struct oflops_context * ctx, const struct ofp_header * ofph)
{
    return 0;
}
int default_module_handle_timer_event(struct oflops_context * ctx, struct timer_event * te)
{
    return 0;
}
int default_module_handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se)
{
    return 0;
}
int default_module_handle_traffic_generation(struct oflops_context * ctx)
{
    return 0;
}

void default_module_of_message(struct oflops_context *ctx, uint8_t of_version, uint8_t type, void *data, size_t len)
{
    switch(type)
    {
    case OFPT_PACKET_IN:
        ctx->curr_test->of_event_packet_in(ctx, (struct ofp_packet_in *)data);
        break;
    case OFPT_FLOW_EXPIRED:
    #ifdef HAVE_OFP_FLOW_EXPIRED
        ctx->curr_test->of_event_flow_removed(ctx, (struct ofp_flow_expired *)data);
    #elif defined(HAVE_OFP_FLOW_REMOVED)
        ctx->curr_test->of_event_flow_removed(ctx, (struct ofp_flow_removed *)data);
    #else
    # error "Unknown version of openflow"
    #endif
        break;
    case OFPT_PORT_STATUS:
        ctx->curr_test->of_event_port_status(ctx, (struct ofp_port_status *)data);
        break;
    case OFPT_ECHO_REQUEST:
        ctx->curr_test->of_event_echo_request(ctx, (struct ofp_header *)data);
        break;
    default:
        if (type > OFPT_BARRIER_REPLY)   // FIXME: update for new openflow versions
        {
            fprintf(stderr, "%s:%d :: Data buffer probably trashed : unknown openflow type %d\n",
                    __FILE__, __LINE__, type);
            abort();
        }
        ctx->curr_test->of_event_other(ctx, (struct ofp_header * ) data);
        break;
    }
}

const uint8_t *default_module_get_openflow_versions() {
    static uint8_t versions[] = {0x1,0x0};
    return versions;
}
