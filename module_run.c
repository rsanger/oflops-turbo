#include "config.h"
#include <assert.h>
#include <dlfcn.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
 #include <poll.h>

#include "module_run.h"
#include "module_default.h"
#include "test_module.h"
#include "utils.h"



static void test_module_loop(oflops_context *ctx, test_module *mod);
static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
static void process_control_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel_name ch);


/******************************************************
 * setup the test
 *
 */
int setup_test_module(oflops_context *ctx, int ix_mod)
{
  struct test_module *mod = ctx->tests[ix_mod];
  int i;
  //Setup
  setup_snmp_channel(ctx);
  for(i=0;i<ctx->n_channels;i++)
    setup_channel( ctx, mod, i);

  timer_init(ctx);
  return 1;
}


/******************************************************
 * call the main loop
 *
 */
int run_test_module(oflops_context *ctx, int ix_mod)
{

  struct test_module *mod = ctx->tests[ix_mod];

  // moved the initialization code in the setup function  as this should
  // happen before thmodule start method
  /* int i; */
  /* //Setup */
  /* setup_snmp_channel(ctx); */
  /* for(i=0;i<ctx->n_channels;i++) */
  /* 	setup_channel( ctx, mod, i); */

  //Run
  test_module_loop(ctx,mod);
  mod->destroy(ctx);

  //Teardown
  teardown_snmp_channel(ctx);

  if((ctx->channels[OFLOPS_CONTROL].dump != NULL) && (ctx->dump_controller))
    pcap_dump_close(ctx->channels[OFLOPS_CONTROL].dump);

  return 0;
}
/******************************************************
 * running traffic generation
 *
 */
int run_traffic_generation(oflops_context *ctx, int ix_mod)
{
  struct test_module *mod = ctx->tests[ix_mod];
  //Run
  mod->handle_traffic_generation(ctx);
  return 0;
}

/********************************************************
 * main loop()
 * 	1) setup poll
 * 	2) call poll with a min timeout of the next event
 * 	3) dispatch events as appropriate
 */
static void test_module_loop(oflops_context *ctx, test_module *mod)
{
    struct pollfd * poll_set;
    int fds = 0;
    int snmpblock = 0;
    fd_set fdset;
    struct timeval timeout;
    int ret;
    int len;
    int ch;
    int n_fds=0;

    len = sizeof(struct pollfd) * (ctx->n_channels + 1);
    poll_set = malloc_and_check(len);

    while(!ctx->end_module)
    {
        n_fds=0;
        bzero(poll_set,len);

        //Channels poll
        for(ch=0; ch< ctx->n_channels; ch++) {
            poll_set[n_fds].fd = ctx->channels[ch].pcap_fd;
            poll_set[n_fds].events = 0;
            if(( ctx->channels[ch].pcap_handle) || (ctx->channels[ch].nf_cap))  {
                poll_set[n_fds].events = POLLIN;
            }

            // it was more efficient to write data on the control channel.
            //
            //if ( msgbuf_count_buffered(ctx->channels[ch].outgoing) > 0)
            //    poll_set[n_fds].events |= POLLOUT;
            if( poll_set[n_fds].events != 0)
                n_fds++;
        }

        //SNMP poll
        FD_ZERO(&fdset);
        timeout.tv_sec = 0;
        timeout.tv_usec = 1;
        /*snmp_select_info(&fds, &fdset, &timeout, &snmpblock);*/
        /*fds = select(fds, &fdset, NULL,NULL, &timeout);*/
        /*if (fds)*/
            /*snmp_read(&fdset);*/

        //  this code was giving me segmentation errors for some reason and I decided
        // to remove it. worst case we just have some memory allocated by the snmp library,
        // but there is plenty of memory.
        //else
        //snmp_timeout();

        // timer events now run on their own thread
        //Timer poll
        /*next_event = timer_get_next_event(ctx);
          while(next_event <= 0 )
          {
          timer_run_next_event(ctx);
          next_event = timer_get_next_event(ctx);
          }*/
        ret = poll(poll_set, n_fds, 1); //next_event);

        if(( ret == -1 ) && ( errno != EINTR))
            perror_and_exit("poll",1);
        else if(ret == 0 ) {
            //if(ctx->should_end == 1) {fprintf(stderr, "finishing poll loop\n"); break;}
            //		  else fprintf(stderr, "not finished yet\n");
            continue; //timer_run_next_event(ctx);
        }
        else // found something to read
        {
            int i;
            for(i=0; i<n_fds; i++) {
                if(poll_set[i].revents & (POLLIN | POLLOUT)) {
                    process_event(ctx, mod, &poll_set[i]);
                }
            }
        }
    }
    free(poll_set);
}

/*******************************************************
 * static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd)
 * a channel got an event
 * 	map the event to the correct channel, and call the appropriate event handler
 *
 * 	FIXME: for efficency, we really should have a faster fd-> channel map, but
 * 		since the number of channels is small, we can just be fugly
 */
static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd)
{
    int ch;

    // this is inefficient, but ok since there are really typically only ~8  cases
    for(ch=0; ch< ctx->n_channels; ch++)
        if (pfd->fd == ctx->channels[ch].pcap_fd) {
            return process_pcap_event(ctx, mod, pfd, ch);
        }
    // only get here if we've screwed up somehow
    fprintf(stderr, "Event on unknown fd %d .. dying", pfd->fd);
    abort();
}

/**********************************************************************************************
 * static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel_name ch);
 * 	front end to oflops_pcap_handler
 * 		make sure all of the memory is kosher before and after
 * 		pcap's callback thing has always annoyed me
 */
static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd, oflops_channel_name ch)
{
    int err;
    const uint8_t *data;
    static pcap_event *pe = NULL;
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;
    struct pcap_event pcap_e;

    if(pfd->revents & POLLOUT) {
        if((err=msgbuf_write(ctx->channels[ch].outgoing,ctx->channels[ch].raw_sock, ctx->channels[ch].packet_len) < 0) &&
                (err != EAGAIN) && (err != EWOULDBLOCK ) && (err != EINTR))
            perror_and_exit("channel write()",1);
    }
    if(!(pfd->revents & POLLIN))		// nothing to read, return
        return;

    // read the next packet from the appropriate pcap socket
    if(ctx->channels[ch].cap_type == PCAP) {
        assert(ctx->channels[ch].pcap_handle);
        err = pcap_next_ex(ctx->channels[ch].pcap_handle, &pkt_header, &pkt_data);

        if (err == 0)
            return;
        if (err < 0)
        {
            fprintf(stderr,"process_pcap_event:pcap_dispatch returned %d :: %s \n", err,
                    pcap_geterr(ctx->channels[ch].pcap_handle));
            return;
        }
        //dump packet if required
        if((ch == OFLOPS_CONTROL) && (ctx->channels[ch].pcap_handle)
                && (ctx->dump_controller)) {
            pcap_dump((u_char *)ctx->channels[ch].dump, pkt_header, pkt_data);
        }

        pcap_e.data = pkt_data;
        memcpy(&pcap_e.pcaphdr, pkt_header, sizeof(pcap_e.pcaphdr));
        // dispatch it to the test module
        if (ctx->started)
            mod->handle_pcap_event(ctx, &pcap_e, ch);
    } else  if(ctx->channels[ch].cap_type == NF2) {
        if(pe == NULL) {
            pe = malloc_and_check(sizeof(pcap_event));
            //This is a hack
            pe->data = malloc_and_check(2000);
        }
        // data = nf_cap_next(ctx->channels[ch].nf_cap, &pe->pcaphdr);
        data = nf_cap_next(ctx->channels[ch].nf_cap, &pe->pcaphdr);

        if(data != NULL) {
            memcpy((char *) pe->data, data, pe->pcaphdr.caplen);
            if (ctx->started)
                mod->handle_pcap_event(ctx,pe, ch);
        } else {
            fprintf(stderr, "errorous packet received\n");
            return;
        }
        free((char *)pe->data);
        free(pe);
    }
    return;
}
/*************************************************************************
 * int load_test_module(oflops_context *ctx,
 * 			char * mod_filename, char * initstr);
 * 	open this module and strip symbols out of it
 * 	and call init() on it
 */
int load_test_module(oflops_context *ctx, char * mod_filename, char * initstr)
{
  void * handle;
  test_module * mod;
  mod = malloc_and_check(sizeof(*mod));
  bzero(mod,sizeof(*mod));

  // open module for dyn symbols
  handle = dlopen(mod_filename,RTLD_NOW);
  if(handle == NULL)
    {
      fprintf(stderr,"Error reading symbols from %s : %s\n",
	      mod_filename, dlerror());
      return 1;
    }
  mod->name = dlsym(handle,"name");
  mod->start = dlsym(handle,"start");
  if(!mod->name)
    fprintf( stderr, "Module %s does not contain a name() function\n", mod_filename);
  if(!mod->start)
    fprintf( stderr, "Module %s does not contain a start() function\n", mod_filename);
  if(!mod->name || !mod->start)
    {
      free(mod);
      dlclose(handle);
      return 1;	// fail for now
    }

#define symbol_fetch(X)				\
  mod->X = dlsym(handle, #X);			\
  if(!mod->X)					\
    mod->X = default_module_##X
  symbol_fetch(init);
  symbol_fetch(destroy);
  symbol_fetch(get_pcap_filter);
  symbol_fetch(handle_pcap_event);
  symbol_fetch(of_event_packet_in);
  symbol_fetch(of_event_flow_removed);
  symbol_fetch(of_event_echo_request);
  symbol_fetch(of_event_port_status);
  symbol_fetch(of_event_other);
  symbol_fetch(handle_timer_event);
  symbol_fetch(handle_snmp_event);
  symbol_fetch(handle_traffic_generation);
  symbol_fetch(of_message);
  symbol_fetch(get_openflow_versions);
#undef symbol_fetch
  if(ctx->n_tests >= ctx->max_tests)
    {
      ctx->max_tests *=2;
      ctx->tests = realloc_and_check(ctx->tests, ctx->max_tests * sizeof(struct test_modules *));
    }
  ctx->tests[ctx->n_tests++] = mod;
  mod->symbol_handle=handle;

  if(mod->init)
    mod->init(ctx, initstr);
  return 0;
}
