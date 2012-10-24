#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sstream>
#include <boost/preprocessor.hpp>

#include "exception.hpp"
#include "util.hpp"

void timestamp(std::ostream& os)
{
    os << "[" << boost::posix_time::second_clock::local_time() << "] ";
}

std::string timestamp()
{
    std::stringstream ss;
    timestamp(ss);
    return ss.str();
}

std::string sockaddr2string(const sockaddr* addr)
{
    if (!addr)
    {
        return "[NULL]";
    }
    char buf[INET6_ADDRSTRLEN];
    std::stringstream ss;
    switch (addr->sa_family)
    {
        case AF_INET:
        {
            const sockaddr_in* addr_in = reinterpret_cast<const sockaddr_in*>(addr);
            if (inet_ntop(AF_INET, &addr_in->sin_addr, buf, INET6_ADDRSTRLEN) == NULL)
            {
                SCTPCAT_THROW(SctpCatError()) << clib_failure("inet_ntop", errno);
            }
            ss << buf << ":" <<  ntohs(addr_in->sin_port);
            break;
        }
        case AF_INET6:
        {
            const sockaddr_in6* addr_in6 = reinterpret_cast<const sockaddr_in6*>(addr);
            if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, buf, INET6_ADDRSTRLEN) == NULL)
            {
                SCTPCAT_THROW(SctpCatError()) << clib_failure("inet_ntop", errno);
            }
            ss << "[" << buf << "]:" << ntohs(addr_in6->sin6_port);
            break;
        }
        default:
        {
            SCTPCAT_THROW(SctpCatError()) << sa_family_info(addr->sa_family);
        }
    }
    return ss.str();
}

std::string sockaddr2string(const sockaddr_storage* addr)
{
    return sockaddr2string(reinterpret_cast<const sockaddr*>(addr));
}

std::string explainRecvmsgFlags(int flags)
{
    if (flags == 0)
    {
        return "0x0";
    }
    std::stringstream ss;
    bool first = true;
#define SCTPCAT_TRY_ONE_FLAG(f) \
    if (flags & f) \
    { \
        if (!first) ss << "|"; \
        ss << #f; \
        first = false; \
        flags ^= f; \
    }
    SCTPCAT_TRY_ONE_FLAG(MSG_NOTIFICATION);
    SCTPCAT_TRY_ONE_FLAG(MSG_EOR);
    SCTPCAT_TRY_ONE_FLAG(MSG_OOB);
    SCTPCAT_TRY_ONE_FLAG(MSG_TRUNC);
    SCTPCAT_TRY_ONE_FLAG(MSG_DONTWAIT);
    SCTPCAT_TRY_ONE_FLAG(MSG_DONTROUTE);
#undef SCTPCAT_TRY_ONE_FLAG
    if (flags != 0)
    {
        if (!first) ss << "|";
        ss << "0x" << std::hex << flags;
    }
    return ss.str();
}

#define SCTPCAT_STRINGIZE_CASE(eid) \
        case eid: \
            return BOOST_PP_STRINGIZE(eid);

#define SCTPCAT_STRINGIZE_CASE_FWD(r, data, item) \
    SCTPCAT_STRINGIZE_CASE(item)

#define SCTPCAT_STRINGIZE_ENUM(ename, evalues) \
const char* BOOST_PP_CAT(stringize_, ename)(const int value) \
{ \
    switch (value) \
    { \
        BOOST_PP_SEQ_FOR_EACH(SCTPCAT_STRINGIZE_CASE_FWD, dummy, evalues) \
        default: \
            return BOOST_PP_STRINGIZE(ename) "_UNKNOWN"; \
    } \
}

#define SCTPCAT_SCTP_SPC_STATES \
    (SCTP_ADDR_AVAILABLE) \
    (SCTP_ADDR_UNREACHABLE) \
    (SCTP_ADDR_REMOVED) \
    (SCTP_ADDR_ADDED) \
    (SCTP_ADDR_MADE_PRIM) \
    (SCTP_ADDR_CONFIRMED)

SCTPCAT_STRINGIZE_ENUM(sctp_spc_state, SCTPCAT_SCTP_SPC_STATES);

#define SCTPCAT_SCTP_SAC_STATES \
    (SCTP_COMM_UP) \
    (SCTP_COMM_LOST) \
    (SCTP_RESTART) \
    (SCTP_SHUTDOWN_COMP) \
    (SCTP_CANT_STR_ASSOC)

SCTPCAT_STRINGIZE_ENUM(sctp_sac_state, SCTPCAT_SCTP_SAC_STATES);

#define SCTPCAT_EVENTS_TYPE_MAP \
    ((SCTP_ASSOC_CHANGE,              sctp_assoc_change)) \
    ((SCTP_PEER_ADDR_CHANGE,          sctp_paddr_change)) \
    ((SCTP_REMOTE_ERROR,              sctp_remote_error)) \
    ((SCTP_SEND_FAILED,               sctp_send_failed)) \
    ((SCTP_SHUTDOWN_EVENT,            sctp_shutdown_event)) \
    ((SCTP_ADAPTATION_INDICATION,     sctp_adaptation_event)) \
    ((SCTP_PARTIAL_DELIVERY_EVENT,    sctp_pdapi_event)) \
    ((SCTP_AUTHENTICATION_INDICATION, sctp_authkey_event))

template <typename T>
void dispatchNotification(sctp_notification* notification, T& consumer)
{
    switch (notification->sn_header.sn_type)
    {
#define SCTPCAT_MAKE_SCTPEVENT_CASE(eid, etype) \
        case eid: \
            { \
                etype* ptr = reinterpret_cast<etype*>(notification); \
                consumer.process(*ptr); \
                break; \
            }
#define SCTPCAT_MAKE_SCTPEVENT_CASE_FWD(r, data, item) \
    SCTPCAT_MAKE_SCTPEVENT_CASE item
    BOOST_PP_SEQ_FOR_EACH(SCTPCAT_MAKE_SCTPEVENT_CASE_FWD, dummy, SCTPCAT_EVENTS_TYPE_MAP)
#undef SCTPCAT_MAKE_SCTPEVENT_CASE_FWD
#undef SCTPCAT_MAKE_SCTPEVENT_CASE
        default:
            SCTPCAT_THROW(SctpCatError());
    }
}

#define SCTPCAT_CHOOSE_ELEM(s, data, elem) BOOST_PP_TUPLE_ELEM(2, 0, elem)

SCTPCAT_STRINGIZE_ENUM(sctp_sn_type,
                       BOOST_PP_SEQ_TRANSFORM(SCTPCAT_CHOOSE_ELEM, dummy, SCTPCAT_EVENTS_TYPE_MAP))

class SctpNotificationPrinter
{
public:
    SctpNotificationPrinter(std::ostream& os)
        : m_os(os)
    {
    }

    template<typename T>
    void process(const T&);

private:

    std::ostream& m_os;
};

template<typename T>
void SctpNotificationPrinter::process(const T& event)
{
    m_os << timestamp();
    m_os << stringize_sctp_sn_type(reinterpret_cast<const sctp_notification*>(&event)->sn_header.sn_type);
}

template<>
void SctpNotificationPrinter::process(const sctp_assoc_change & event)
{
    m_os << stringize_sctp_sn_type(event.sac_type);
    m_os << " assoc_id: " << event.sac_assoc_id;
    m_os << " state: " << stringize_sctp_sac_state(event.sac_state);
    m_os << " error: " << event.sac_error;
    m_os << " os: " << event.sac_outbound_streams;
    m_os << " is: " << event.sac_inbound_streams;
}

template<>
void SctpNotificationPrinter::process(const sctp_paddr_change & event)
{
    m_os << stringize_sctp_sn_type(event.spc_type);
    m_os << " assoc_id: " << event.spc_assoc_id;
    m_os << " addr: " << sockaddr2string(&event.spc_aaddr);
    m_os << " state: " << stringize_sctp_spc_state(event.spc_state);
    m_os << " error: " << event.spc_error;
    m_os << " flags: " << event.spc_flags;
}

void printSctpNotification(std::ostream& os, sctp_notification* n)
{
    SctpNotificationPrinter snp(os);
    os << timestamp();
    dispatchNotification(n, snp);
}

