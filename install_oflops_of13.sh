# Don't run as root, just copy and run the apt line as root
# Install what we can from apt, this is correct for ubuntu/debian
# apt install git libtool build-essential autoconf libconfig-dev libpcap-dev libsnmp-dev libgsl-dev libssl-dev

# NOTE We patch libfluid and use a newer libevent release TODO for SSL

# But if we need particular versions build those ourselves
set -e

#Build and install locally
mkdir -p build
export CFLAGS="-I$(pwd)/build/include -Wno-error=deprecated"
export CPPFLAGS="-I$(pwd)/build/include -Wno-error=deprecated"
export CXXFLAGS="-I$(pwd)/build/include -Wno-error=deprecated"
export LDFLAGS="-L$(pwd)/build/lib"
export PKG_CONFIG_PATH="$(pwd)/build/lib/pkgconfig/"

# Ready the openflow library
git clone git://gitosis.stanford.edu/openflow
cd openflow
./boot.sh
./configure --prefix=$(pwd)/../build
make
make install
cd ..

# Ready a local libevent, pre-2.1 hangs when doing ssl
git clone https://github.com/libevent/libevent.git
cd libevent
git checkout release-2.1.8-stable
./autogen.sh
./configure --prefix=$(pwd)/../build
make
make install
cd ..


# Ready the libfluid_base library
git clone https://github.com/OpenNetworkingFoundation/libfluid.git
cd libfluid
./bootstrap.sh
cd libfluid_base
git checkout 56df5e20c49387ab8e6b5cd363c6c10d309f263e
# PATCH for new libevent, works with SSL and get_fd for NO_DELAY
git apply <<EOF
diff --git a/fluid/OFConnection.cc b/fluid/OFConnection.cc
index 3823ba3..ecc64f0 100644
--- a/fluid/OFConnection.cc
+++ b/fluid/OFConnection.cc
@@ -46,6 +46,10 @@ OFHandler* OFConnection::get_ofhandler() {
     return this->ofhandler;
 }
 
+int OFConnection::get_fd() {
+    return this->conn->get_fd();
+}
+
 void OFConnection::send(void* data, size_t len) {
     if (this->conn != NULL)
         this->conn->send((uint8_t*) data, len);
diff --git a/fluid/OFConnection.hh b/fluid/OFConnection.hh
index dc3af4e..c2adaea 100644
--- a/fluid/OFConnection.hh
+++ b/fluid/OFConnection.hh
@@ -106,6 +106,9 @@ public:
     */
     OFHandler* get_ofhandler();
 
+#define HAS_GET_FD 1
+    int get_fd();
+
     /**
     Send data to through the connection.
 
diff --git a/fluid/base/BaseOFConnection.cc b/fluid/base/BaseOFConnection.cc
index 09c3191..a29365e 100644
--- a/fluid/base/BaseOFConnection.cc
+++ b/fluid/base/BaseOFConnection.cc
@@ -216,6 +216,10 @@ BaseOFConnection::~BaseOFConnection() {
     delete this->m_implementation;
 }
 
+int BaseOFConnection::get_fd() {
+    return bufferevent_getfd(this->m_implementation->bev);
+}
+
 void BaseOFConnection::send(void* data, size_t len) {
     bufferevent_write(this->m_implementation->bev, data, len);
 }
diff --git a/fluid/base/BaseOFConnection.hh b/fluid/base/BaseOFConnection.hh
index 0c5257b..0f5910c 100644
--- a/fluid/base/BaseOFConnection.hh
+++ b/fluid/base/BaseOFConnection.hh
@@ -49,6 +49,8 @@ public:
         EVENT_CLOSED
     };
 
+    int get_fd();
+
     /**
     Send a message through this connection.
 
diff --git a/fluid/base/EventLoop.cc b/fluid/base/EventLoop.cc
index b583667..4d69069 100644
--- a/fluid/base/EventLoop.cc
+++ b/fluid/base/EventLoop.cc
@@ -7,10 +7,6 @@ namespace fluid_base {
 // Define our own value, since the stdint.h define doesn't work in C++
 #define OF_MAX_LEN 0xFFFF
 
-// See FIXME in EventLoop::EventLoop
-extern "C" void event_base_add_virtual(struct event_base *);
-extern "C" void event_base_del_virtual(struct event_base *);
-
 class EventLoop::LibEventEventLoop {
 private:
     friend class EventLoop;
@@ -29,19 +25,6 @@ EventLoop::EventLoop(int id) {
         exit(EXIT_FAILURE);
     }
 
-    /* FIXME: dirty hack warning!
-    We add a virtual event to prevent the loop from exiting when there are
-    no events.
-
-    This fix is needed because libevent 2.0 doesn't have the flag
-    EVLOOP_NO_EXIT_ON_EMPTY. Version 2.1 fixes this, so this will have to
-    be changed in the future (to make it prettier and to avoid breaking
-    anything).
-
-    See:
-    http://stackoverflow.com/questions/7645217/user-triggered-event-in-libevent
-    */
-    event_base_add_virtual(this->m_implementation->base);
 }
 
 EventLoop::~EventLoop() {
@@ -54,10 +37,7 @@ void EventLoop::run() {
     if (stopped) return;
 
     event_base_dispatch(this->m_implementation->base);
-    // See note in EventLoop::EventLoop. Here we disable the virtual event
-    // to guarantee that nothing blocks.
-    event_base_del_virtual(this->m_implementation->base);
-    event_base_loop(this->m_implementation->base, EVLOOP_NONBLOCK);
+    event_base_loop(this->m_implementation->base, EVLOOP_NONBLOCK|EVLOOP_NO_EXIT_ON_EMPTY);
 }
 
 void EventLoop::stop() {
EOF
./configure --prefix=$(pwd)/../../build
make
make install
cd ../..

# Ready librofl
# Has minor bugs see git diff under C++11 standard
git clone https://github.com/bisdn/rofl-common
cd rofl-common
git checkout v0.6.1
# Fixes for C++11 compile
git apply <<EOF
diff --git a/src/rofl/common/caddress.cc b/src/rofl/common/caddress.cc
index dbf7ecc8..abc77024 100644
--- a/src/rofl/common/caddress.cc
+++ b/src/rofl/common/caddress.cc
@@ -42,7 +42,7 @@ void
 caddress_ll::str2addr(
 		const std::string& addr)
 {
-    sscanf(addr.c_str(), "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
+    sscanf(addr.c_str(), "%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8,
                     (uint8_t*)&((*this)[0]),
                     (uint8_t*)&((*this)[1]),
                     (uint8_t*)&((*this)[2]),
diff --git a/tools/spray/cudprecv.cc b/tools/spray/cudprecv.cc
index ea37659a..f6b61df0 100644
--- a/tools/spray/cudprecv.cc
+++ b/tools/spray/cudprecv.cc
@@ -260,7 +260,7 @@ cudprecv::print_statistics()
 	double loss = 100 * ((double)rxlost / npkts);
 	double bitrate = (double)(8 * rxbytes) / (stoptime - starttime) / 1000000;
 
-	fprintf(stdout, "rxseqno: %"PRIu64" rxbytes: %"PRIu64" rxlost: %"PRIu64" npkts: %"PRIu64" rxrcvd: %"PRIu64" loss: %lf%% bitrate: %.6lfMbps\n",
+	fprintf(stdout, "rxseqno: %" PRIu64 " rxbytes: %" PRIu64 " rxlost: %" PRIu64 " npkts: %" PRIu64 " rxrcvd: %" PRIu64 " loss: %lf%% bitrate: %.6lfMbps\n",
 			rxseqno, rxbytes, rxlost, rxseqno - startseqno, rxrcvd, loss, bitrate);
 
 	if (keep_going)
diff --git a/tools/spray/cudpsend.cc b/tools/spray/cudpsend.cc
index 26a70258..ecd6a2ea 100644
--- a/tools/spray/cudpsend.cc
+++ b/tools/spray/cudpsend.cc
@@ -229,7 +229,7 @@ void
 cudpsend::print_statistics()
 {
 	double bitrate = (double)(8 * txbytes) / (stoptime - starttime) / 1000000;
-	fprintf(stderr, "txbytes: %"PRIu64" npkts: %"PRIu64" bitrate: %.6lfMbps\n", txbytes, npkts, bitrate);
+	fprintf(stderr, "txbytes: %" PRIu64 " npkts: %" PRIu64 " bitrate: %.6lfMbps\n", txbytes, npkts, bitrate);
 
 	if (keep_going)
 		register_timer(CUDPSEND_TIMER_PRINT_STATS, stats_interval);
EOF
./autogen.sh
./configure --prefix=$(pwd)/../build
make -j8
make install
cd ..


# Ready oflops
git clone https://github.com/wandsdn/oflops-turbo.git
cd oflops-turbo
git checkout wip_of13
./boot.sh
./configure --prefix=$(pwd)/../build
make -j8
cd ..


