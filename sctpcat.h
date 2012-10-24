#ifndef SCTPCAT_H
#define SCTPCAT_H
#include <boost/program_options.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <netdb.h>
#include <netinet/sctp.h>
#include <string>

#include "isctpsink.h"

class SctpCat : public ISctpSink
{
public:
    typedef boost::program_options::variables_map varmap;

    SctpCat(const varmap& options);
    void setup(std::string host, const std::string& port);
    void listenSocket();
    void connectSocket(const std::string &host, const std::string &port);
    void receiveLoop();
    void send(const char* buf, size_t len);
    void setPathMaxRetrans(sctp_assoc_t assoc_id, int count);
    void setAssocMaxRetrans(sctp_assoc_t assoc_id, int count);
    void setRto(int rtoMin, int rtoMax, int rtoInitial);

    void registerAssociationCallback(boost::function<void(int, sctp_assoc_t)>);
    void registerPeerAddressCallback(boost::function<void(int, sctp_assoc_t, const sockaddr_storage&)>);
private:
    void subscribeAllEvents(int fd);
    int setupSocket(int ai_family, sockaddr* local_addr, socklen_t local_addr_len);

    void receiveMessages(int fd);
    void processMessage(int fd, char* buf, int len, sockaddr* from, socklen_t fromlen,
                        const sctp_sndrcvinfo& sinfo, int flags);
    int m_fd;
    sctp_assoc_t m_assoc_id;
    static const int s_maxPendingConnections = 10;
    bool m_printTicks;
    int m_aiFamily;
    bool m_listen;
    const varmap& m_options;
    boost::shared_ptr<addrinfo> m_ai;
    mutable boost::mutex m_mutex;
    typedef boost::mutex::scoped_lock ScopedLock;
    std::vector< boost::function<void(int, sctp_assoc_t)> > m_associationCallbacks;
    std::vector< boost::function<void(int, sctp_assoc_t, const sockaddr_storage&)> > m_peerAddresssCallbacks;
};


#endif // SCTPCAT_H
