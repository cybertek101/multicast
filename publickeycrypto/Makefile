
CXX       = arm-none-linux-gnueabi-g++  
#/home/tech/arm-2010q1/bin/arm-none-linux-gnueabi-g++ 
AR        = /usr/bin/ar
CXXFLAGS  = -I/home/tech/arm-2010q1/arm-none-linux-gnueabi/include/c++/4.4.1/ -march=armv7-a -mtune=cortex-a9 -mfpu=neon  -g  -Wall -std=c++0x -std=gnu++0x
# LIBS      = -lm -lpthread -lcrypto -lssl -lcryptopp -lsqlite3 -lmysqlcppconn -lz  # ©-lrt -lmysqlclient 
LIBS      =  -L/home/tech/arm-2010q1/lib/gcc/arm-none-linux-gnueabi/4.4.1/ -leay32 -lssleay32  -lm -lpthread  -lrt
#LIBS      = -L/usr/lib/gcc-cross/arm-linux-gnueabi/4.7 -leay32 -lssleay32  -lm -lpthread 

#NODES   = CDAXNode SecurityServerNode
CLIENTS = test_smartmeter test_utilityserver PMUAdapter PDCAdapter # ReplayClient Monitor

OBJS1 = CryptoBoxOpenSSL.o EncodeDecode.o MsgDistributor.o MsgReceiver.o MsgSessionPool.o Thread.o ConnMgr.o Conn.o ConnTable.o SecurityServer.o ConnMonitor.o
OBJS2 = PubDN.o SubDN.o PubSub.o Publisher.o 
OBJS3 = PubSub.o Publisher.o Subscriber.o

#OBJS2 = Resolver.o DataBroker.o PubDN.o SubDN.o PubSub.o Publisher.o MonitorDataGatherer.o
#OBJS3 = PubSub.o Publisher.o Subscriber.o
 

all:  clients #nodes

#nodes: $(NODES)

clients: $(CLIENTS)


#CDAXNode: CDAXNode.cc libcdax_node.a libcdax_common.a
#	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	 
SecurityServerNode: SecurityServerNode.cc libcdax_node.a libcdax_common.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	
test_smartmeter: test_smartmeter.cc libcdax_client.a libcdax_common.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	 
test_utilityserver: test_utilityserver.cc libcdax_client.a libcdax_common.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

PMUAdapter: PMUAdapter.cc libcdax_client.a libcdax_common.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

PDCAdapter: PDCAdapter.cc libcdax_client.a libcdax_common.a	
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

#ReplayClient: ReplayClient.cc libcdax_client.a libcdax_common.a
#	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	
Monitor: Monitor.cc libcdax_client.a libcdax_common.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	
libcdax_common.a: $(OBJS1) 
	$(AR) rcs $@ $^

libcdax_node.a: $(OBJS2) 
	$(AR) rcs $@ $^

libcdax_client.a: $(OBJS3) 
	$(AR) rcs $@ $^

%.o: %.cc %.h CommDefs.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

#CryptoBox.o: CryptoBox.cpp CryptoBox.h CommDefs.h
#	$(CXX) $(CXXFLAGS) -o $@ -c $<

CryptoBoxOpenSSL.o: CryptoBoxOpenSSL.cpp CryptoBoxOpenSSL.h CommDefs.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

EncodeDecode.o: EncodeDecode.cpp EncodeDecode.h CryptoBoxOpenSSL.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

SecurityServer.o: SecurityServer.cpp SecurityServer.h ConnMgr.h MsgReceiver.h CryptoBoxOpenSSL.h  ConnMonitor.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a *.pkey *.skey *.db *.delays $(NODES) $(CLIENTS)

