#include <fluid/OFServer.hh>
#include <fluid/OFServerSettings.hh>
#include <fluid/TLS.hh>
extern "C" {
#include "control.h"
#include "utils.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "event2/event.h"
#include <poll.h>
#include <netinet/tcp.h>
}
#include <condition_variable>
#include <iostream>

#include <netinet/in.h>
#include <iostream>

std::condition_variable wait_connected;
std::mutex wait_connected_m;

/* A conversion layer between C and C++ allowing us to
 * use the libfluid base to handle our connection */

class BasicTestServer : public fluid_base::OFServer{
public:
    oflops_context *ctx;
    static bool onlydelete;
    using fluid_base::OFServer::OFServer;
    using fluid_base::OFServer::start;
    using fluid_base::OFServer::stop;
    fluid_base::OFConnection::Event state;

    virtual void message_callback(fluid_base::OFConnection* ofconn, uint8_t type, void* data, size_t len) {
        if (ctx->curr_test == NULL)
            return;
        ctx->curr_test->of_message(ctx, ofconn->get_version(), type, data, len);
    }

    virtual void connection_callback(fluid_base::OFConnection* ofconn, fluid_base::OFConnection::Event type) {
        using namespace fluid_base;
        switch(type) {
        case OFConnection::EVENT_STARTED:
            std::cout<<"Connection id="<<ofconn->get_id()<<" started"<<std::endl;
            break;
        case OFConnection::EVENT_ESTABLISHED:
            std::cout<<"Connection id="<<ofconn->get_id()<<" established"<<std::endl;
            break;
        case OFConnection::EVENT_FAILED_NEGOTIATION:
            std::cout<<"Connection id="<<ofconn->get_id()<<" failed version negotiation"<<std::endl;
            break;
        case OFConnection::EVENT_CLOSED:
            std::cout<<"Connection id="<<ofconn->get_id()<<" closed by the user"<<std::endl;
            break;
        case OFConnection::EVENT_DEAD:
            std::cout<<"Connection id="<<ofconn->get_id()<<" closed due to inactivity"<<std::endl;
            break;
        }
        {
        std::unique_lock<std::mutex> locker(wait_connected_m);
        state = type;
        }
        wait_connected.notify_all();
    }
    bool has_backlog(){
        fluid_base::OFConnection *conn = get_ofconnection(0);
        struct pollfd fds = {0};
        fds.fd = conn->get_fd();
        fds.events = POLLOUT;
        poll(&fds, 1, 0);

        return fds.revents&POLLOUT ? false : true;
    }
};

static int check_of_version_allowed(oflops_context *ctx, uint8_t v) {
    if (ctx->nb_of_versions == 0)
        return 1;
    for (size_t i = 0; i < ctx->nb_of_versions; i++) {
        if (v == ctx->of_versions[i])
            return 1;
    }
    return 0;
}

extern "C" int setup_control_channel(oflops_context *ctx) {
    using namespace fluid_base;
    int fd;
    struct sockaddr_in *sinptr;
    struct ifreq ifr;
    OFServerSettings options;
    int one = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /*
     * Get the name of the interface on which the socket was opened.
     */
    strncpy(ifr.ifr_name,ctx->channels[OFLOPS_CONTROL].dev,IFNAMSIZ);
    if( ioctl( fd, SIOCGIFADDR, &ifr)  == -1 )
      perror_and_exit("ioctl() SIOCGIFADDR to dev",1);

    close(fd);
    sinptr = (struct sockaddr_in *) & ifr.ifr_addr;
    char *address = inet_ntoa(sinptr->sin_addr);

    bool use_tls = false;
    if (ctx->tls_cert && ctx->tls_privkey && ctx->tls_trustedcert) {
        std::cerr<<"using tls!!\n";
        fluid_base::libfluid_tls_init(ctx->tls_cert, ctx->tls_privkey, ctx->tls_trustedcert);
        use_tls = true;
    }
    if (ctx->curr_test->get_openflow_versions()) {
        const uint8_t *ofvs = ctx->curr_test->get_openflow_versions();
        std::cout<<"Adding openflow versions ";
        for (int i = 0; ofvs[i]; i++) {
            if (check_of_version_allowed(ctx, ofvs[i])) {
                std::cout<<(int) ofvs[i]<<"," ;
                options.supported_version(ofvs[i]);
            }
        }
        std::cout<<" to openflow handshake"<<std::endl;
    }
    options.echo_interval(10000);

    auto ser = new BasicTestServer(address, ctx->listen_port, 1, use_tls, options);
    ctx->fluid_control = static_cast<void *>(ser);
    ser->ctx = ctx;
    ser->state = OFConnection::EVENT_DEAD;
    ser->start();
    std::cout<<"Waiting for a switch to connect...\n";
    // Wait for connection?
    std::unique_lock<std::mutex> locker(wait_connected_m);
    while ((ser->get_ofconnection(0) == NULL
           || ser->get_ofconnection(0)->get_state() == OFConnection::STATE_HANDSHAKE)
           && ser->state != OFConnection::EVENT_FAILED_NEGOTIATION) {
        wait_connected.wait(locker);
    }
    if (ser->get_ofconnection(0)->get_state() == OFConnection::STATE_FAILED ||
            ser->state == OFConnection::EVENT_FAILED_NEGOTIATION) {
        std::cerr<<"Connection failed, likely failed negotiation."<<std::endl;
        abort();
    }
    fd =ser->get_ofconnection(0)->get_fd();
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
            std::cerr<<"Failed to disable nagle!!"<<std::endl;
    }

    std::cout<<"Ready to generate!!"<<std::endl;
    ctx->of_version = ser->get_ofconnection(0) ? ser->get_ofconnection(0)->get_version() : 0;
    return 0;
}

extern "C" void teardown_control_channel(oflops_context *ctx) {
    BasicTestServer *test = static_cast<BasicTestServer *>(ctx->fluid_control);
    test->stop();
    delete test;
    ctx->fluid_control = NULL;
}

extern "C" int write_oflops_control(oflops_context *ctx, void* data, size_t len) {
    BasicTestServer *test = static_cast<BasicTestServer *>(ctx->fluid_control);

    if (len == 0) {
        len = ntohs(((struct ofp_header *) data)->length);
    }
    test->get_ofconnection(0)->send(data, len);
    return 0;
}

extern "C" int has_backlog(oflops_context *ctx) {
    BasicTestServer *test = static_cast<BasicTestServer *>(ctx->fluid_control);
    return test->has_backlog();
}
