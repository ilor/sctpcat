#include <iostream>
#include <sstream>
#include <vector>

#include <arpa/inet.h>

#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/program_options.hpp>

#include <boost/thread.hpp>

#include "addrinfo.hpp"
#include "exception.hpp"
#include "util.hpp"

typedef boost::program_options::variables_map varmap;

class SctpCat
{
public:
    SctpCat(const varmap& options);
    void setup(std::string host, const std::string& port);
    void listenSocket();
    void connectSocket(const std::string &host, const std::string &port);
    void receiveLoop();
    void pingLoop(int bytes, int interval);
    void consoleLoop();
    void send(const char* buf, size_t len);
    void setPathMaxRetrans(sctp_assoc_t assoc_id, int count);
    void setAssocMaxRetrans(sctp_assoc_t assoc_id, int count);
    void setRto(int rtoMin, int rtoMax, int rtoInitial);
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
    std::vector< boost::function<void(sctp_assoc_t)> > m_newAssocCallbacks;
    std::vector< boost::function<void(sctp_assoc_t, sockaddr_storage&)> > m_newPaddrCallbacks;
};

SctpCat::SctpCat(const varmap& options)
    : m_fd(-1), m_options(options)
{
    m_printTicks = options.count("ticks");
    m_aiFamily = options.count("ipv6") ? AF_INET6 : AF_INET;
    m_listen = options.count("listen");
}

int SctpCat::setupSocket(int ai_family, sockaddr* local_addr, socklen_t local_addr_len)
{
    std::cerr << "setup socket for " << ai_family << " " << sockaddr2string(local_addr) << "\n";
    int fd = socket(ai_family, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (fd == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("socket", errno);
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("fcntl get", errno);
    }
    if (fcntl(fd, F_SETFL, flags|O_NONBLOCK) == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("fcntl set", errno);
    }
    if (local_addr)
    {
        if (bind(fd, local_addr, local_addr_len) == -1)
        {
            SCTPCAT_THROW(SctpCatError()) << clib_failure("bind", errno);
        }
    }
    subscribeAllEvents(fd);
    std::cerr << "Socket open, fd=" << fd << "\n";
    return fd;
}

void SctpCat::listenSocket()
{
    if (listen(m_fd, s_maxPendingConnections) == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("listen", errno);
    }
}

void SctpCat::subscribeAllEvents(int fd)
{
    struct sctp_event_subscribe event;
    memset(&event, 0, sizeof(event));

    event.sctp_adaptation_layer_event = 1;
    event.sctp_address_event = 1;
    event.sctp_authentication_event = 1;
    event.sctp_association_event = 1;
    event.sctp_data_io_event = 1;
    event.sctp_partial_delivery_event = 1;
    event.sctp_peer_error_event = 1;
    event.sctp_send_failure_event = 1;
    event.sctp_shutdown_event = 1;

    if (setsockopt(fd, SOL_SCTP, SCTP_EVENTS, &event, socklen_t(sizeof(event))) != 0)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("setsockopt", errno);
    }
}

void disableHb(int fd, sctp_assoc_t assoc_id, void* addr, size_t addr_len)
{
    sctp_paddrparams params;
    memset(&params, 0, sizeof(params));
    params.spp_flags = SPP_HB_DISABLE;
    params.spp_assoc_id = assoc_id;
    memcpy(&params.spp_address, addr, addr_len);
    if (setsockopt(fd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS, &params, socklen_t(sizeof(params))) != 0)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("setsockopt", errno);
    }
    std::cerr << timestamp() << "Disabled HB on " << sockaddr2string(reinterpret_cast<sockaddr*>(addr)) << "\n";
}

void SctpCat::receiveLoop()
{
    int epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("epoll_create1", errno);
    }
    epoll_event eev;
    memset(&eev, 0, sizeof(eev));
    eev.events = EPOLLIN | EPOLLET;
    eev.data.fd = m_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, m_fd, &eev) == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("epoll_ctl", errno);
    }
    for (;;)
    {
        epoll_event events[10];
        int nfds = epoll_wait(epollfd, events, 10, 10000);
        if (nfds == -1)
        {
            SCTPCAT_THROW(SctpCatError()) << clib_failure("epoll_wait", errno);
        }
        ScopedLock lock(m_mutex);
        for (int i = 0; i < nfds; ++i)
        {
            receiveMessages(events[i].data.fd);
        }
        if (m_printTicks)
        {
            std::cerr << "epoll tick\n";
        }
    }
}

void SctpCat::pingLoop(int bytes, int interval)
{
    std::vector<char> buf(bytes);
    for (int i = 0; i < bytes; ++i)
    {
        buf[i] = 'A' + (i % ('Z' - 'A'));
    }
    for (;;)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
        if (m_assoc_id == 0)
        {
            std::cerr << timestamp() << "No association, not pinging";
        }
        else
        {
            send(&buf[0], bytes);
        }
    }
}

void SctpCat::send(const char* buf, size_t len)
{
    ScopedLock(m_mutex);
    sctp_sndrcvinfo sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.sinfo_assoc_id = m_assoc_id;
    uint32_t flags = MSG_NOSIGNAL;
    int rv = sctp_send(m_fd, buf, len, &sinfo, flags);
    //int rv = sctp_sendmsg(m_fd, &buf[0], bytes, m_ai->ai_addr, m_ai->ai_addrlen, 9, flags, 1, 0, 0);
    if (rv == -1)
    {
        std::cerr << timestamp() << "sctp_send " << m_fd << " " 
            << buf[0] << " " << len << " returned " << rv 
            << ", error is " << strerror(errno) << "\n";
    }
    else
    {
        std::cerr << timestamp() << "sent " << rv << " bytes, tsn " << sinfo.sinfo_tsn << "\n";
    }
}

void SctpCat::consoleLoop()
{
    for (;;)
    {
        std::string input;
        std::getline(std::cin, input);
        if (!input.empty())
        {
            send(input.c_str(), input.size());
        }
    }
}

void SctpCat::receiveMessages(int fd)
{
    const int msgbufsize = 2000;
    char msgbuf[msgbufsize] = {0};
    sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    sockaddr* from_ptr = reinterpret_cast<sockaddr*>(&from);
    sctp_sndrcvinfo sinfo;
    int flags = 0;

    for (;;)
    {
        int recvbytes = sctp_recvmsg(fd, msgbuf, msgbufsize, from_ptr, &fromlen, &sinfo, &flags);
        if (recvbytes == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            SCTPCAT_THROW(SctpReceiveError()) << clib_failure("sctp_recvmsg", errno);
        }
        //std::cerr << "x " << (int)from_ptr->sa_family << " " << fromlen << "\n";
        processMessage(fd, msgbuf, recvbytes, from_ptr, fromlen, sinfo, flags);
    }
}

void SctpCat::processMessage(int fd, char* buf, int len, sockaddr* from, socklen_t fromlen,
                             const sctp_sndrcvinfo& sinfo, int flags)
{
    std::cerr << timestamp();
    std::cerr << "Received " << len << " bytes on fd " << fd << " from " << sockaddr2string(from)
              << " assoc " << sinfo.sinfo_assoc_id << " tsn " << sinfo.sinfo_tsn
              << " with flags " << explainRecvmsgFlags(flags) << "\n";
    if (flags & MSG_NOTIFICATION)
    {
        sctp_notification* notify = reinterpret_cast<sctp_notification*>(buf);
        if (notify->sn_header.sn_type == SCTP_ASSOC_CHANGE)
        {
            if (notify->sn_assoc_change.sac_state == SCTP_COMM_UP)
            {
                m_assoc_id = notify->sn_assoc_change.sac_assoc_id;
                ptrdiff_t info_from = offsetof(sctp_assoc_change, sac_info);
                ptrdiff_t info_to = len;
                std::cerr << timestamp() << "COMM_UP on assoc_id " << m_assoc_id << "\n";
            }
        }
        if (notify->sn_header.sn_type == SCTP_PEER_ADDR_CHANGE)
        {
            if (notify->sn_paddr_change.spc_state == SCTP_ADDR_CONFIRMED)
            {
                if (m_options.count("no-hb-on-secondary"))
                {
                    disableHb(fd, notify->sn_paddr_change.spc_assoc_id, &notify->sn_paddr_change.spc_aaddr, sizeof(notify->sn_paddr_change.spc_aaddr));
                }
            }
        }
        printSctpNotification(std::cerr, notify);
        std::cerr << "\n";
    }
}

void SctpCat::setup(std::string host, const std::string &port)
{
    std::cout << "setup " << host << " : " << port << "\n";
    if (!host.empty())
    {
        boost::shared_ptr<addrinfo> ai = getAi(m_aiFamily, port, host, m_listen);
        m_fd = setupSocket(ai->ai_family, ai->ai_addr, ai->ai_addrlen);
    }
    else
    {
        if (host.empty() && port.empty())
        {
            if (m_options.count("ipv6"))
            {
                m_fd = setupSocket(AF_INET, NULL, 0);
            }
            else
            {
                m_fd = setupSocket(AF_INET6, NULL, 0);
            }
        }
        else
        {
            if (m_options.count("ipv6"))
            {
                host = "::1";
            }
            else
            {
                host = "0.0.0.0";
            }
            boost::shared_ptr<addrinfo> ai = getAi(m_aiFamily, port, host, m_listen);
            m_fd = setupSocket(ai->ai_family, ai->ai_addr, ai->ai_addrlen);
        }
    }
}

void SctpCat::connectSocket(const std::string& host, const std::string &port)
{
    boost::shared_ptr<addrinfo> ai = getAi(m_aiFamily, port, host, false);
    std::cerr << ai->ai_family << "/" << AF_INET << "/" << AF_INET6 << " "
              << sockaddr2string(ai->ai_addr) << "\n";
    if (connect(m_fd, ai->ai_addr, ai->ai_addrlen) == -1)
    {
        switch (errno)
        {
            case EINPROGRESS:
                std::cerr << "Connect in progress\n";
                break;
            case EALREADY:
                std::cerr << "Connect already in progress\n";
                break;
            default:
                SCTPCAT_THROW(SctpCatError()) << clib_failure("connect", errno);
        }
    }
    m_ai = ai;
}

void SctpCat::setPathMaxRetrans(sctp_assoc_t assoc_id, int count)
{
    struct sctp_paddrparams params;
    memset(&params, 0, sizeof(params));
    params.spp_assoc_id = assoc_id;
    params.spp_pathmaxrxt = count;
    if (setsockopt(m_fd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS, &params, socklen_t(sizeof(params))) != 0)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("setsockopt", errno);
    }
}

void SctpCat::setAssocMaxRetrans(sctp_assoc_t assoc_id, int count)
{
    struct sctp_assocparams params;
    memset(&params, 0, sizeof(params));
    params.sasoc_assoc_id = assoc_id;
    params.sasoc_asocmaxrxt = count;
    if (setsockopt(m_fd, SOL_SCTP, SCTP_ASSOCINFO, &params, socklen_t(sizeof(params))) != 0)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("setsockopt", errno);
    }
}

int main(int argc, char** argv)
{
    namespace po = boost::program_options;
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help,h", "Produce help message")
            ("ticks", po::value<bool>()->zero_tokens(), "Print loop ticks")
            ("timestamps", "Timestamp received messages and events")
            ("assoc-max-retrans", po::value<int>(), "SCTP Association Max Retransmissions")
            ("path-max-retrans", po::value<int>(), "SCTP Path Max Retransmissions")
            ("ipv6,6", "Use IPv6")
            ("listen,l", "Listen mode")
            ("local-port", po::value<std::string>(), "Local bind port (connect mode)")
            ("host-port", po::value< std::vector<std::string> >()->composing(), "Host-port to connect to or listen at")
            ("ping-bytes", po::value<int>()->default_value(300), "Ping bytes")
            ("ping-interval", po::value<int>(), "Ping interval (ms)")
            ("no-hb-on-secondary", "Disable heartbeats on secondary (multihomed) addresses")
            ("debug", "Debug prints")
            ;
    po::positional_options_description pd;
    pd.add("host-port", -1);

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);
        po::notify(vm);
    }
    catch (boost::exception & e)
    {
        std::cerr << boost::diagnostic_information(e);
    }

    if (vm.count("help"))
    {
        std::cout << argv[0] << " [OPTIONS] [HOST][:]PORT\n";
        std::cout << desc << "\n";
        return 1;
    }

    if (!vm.count("host-port"))
    {
        std::cerr << "Need a host-port argument\n";
        return 2;
    }

    std::vector<std::string> hp = vm["host-port"].as< std::vector<std::string> >();
    if (hp.size() == 1 && !vm.count("ipv6"))
    {
        std::string str = hp[0];
        size_t colon = str.rfind(":");
        if (colon != std::string::npos)
        {
            hp[0] = str.substr(0, colon);
            hp.push_back(str.substr(colon + 1));
        }
    }
    if (hp.size() > 2)
    {
        std::cerr << "Too many host-port elements (" << vm.count("host-port") << ")\n";
        return 2;
    }

    std::string host, port;
    if (hp.size() == 1)
    {
        if (vm.count("listen"))
        {
            port = hp[0];
        }
        else
        {
            std::cerr << "Port argument required to connect to remote host\n";
            return 2;
        }
    }
    else
    {
        host = hp[0];
        port = hp[1];
    }

    if (vm.count("debug"))
    {
#ifdef HAVE_SCTP_MULTIBUF
        std::cout << "SCTP MULTIBUF is available\n";
#endif
        std::cout << "sockaddr sockaddr_in sockaddr_in6 sockaddr_storage in_addr in6_addr\n";
        std::cout << sizeof(sockaddr) << " " << sizeof(sockaddr_in) << " " << sizeof(sockaddr_in6) << " "
                  << sizeof(sockaddr_storage) << " " << sizeof(in_addr) << " " << sizeof(in6_addr) << "\n";
    }
    try
    {
        SctpCat sc(vm);
        if (vm.count("listen"))
        {
            sc.setup(host, port);
            sc.listenSocket();
        }
        else
        {
            if (vm.count("local-port"))
            {
                sc.setup("", vm["local-port"].as<std::string>());
            }
            else
            {
                sc.setup("", "");
            }
            sc.connectSocket(host, port);
        }
        if (vm.count("ping-interval"))
        {
            boost::thread ping_thread(boost::bind(&SctpCat::pingLoop, &sc, vm["ping-bytes"].as<int>(), vm["ping-interval"].as<int>()));
        }
        boost::thread ping_thread(boost::bind(&SctpCat::consoleLoop, &sc));
        sc.receiveLoop();
    }
    catch (boost::exception & e)
    {
        std::cerr << boost::diagnostic_information(e);
    }
}
