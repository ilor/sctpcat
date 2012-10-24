#ifndef SCTPCAT_UTIL_HPP
#define SCTPCAT_UTIL_HPP

#include <sys/socket.h>
#include <netinet/sctp.h>
#include <string>
#include <iosfwd>
#include <boost/date_time/posix_time/posix_time.hpp>

std::string sockaddr2string(const sockaddr* addr);
std::string sockaddr2string(const sockaddr_storage* addr);

std::string explainRecvmsgFlags(int flags);

const char* stringize_sctp_sac_state(sctp_sac_state value);
const char* stringize_sctp_sn_type(sctp_sn_type value);

void printSctpNotification(std::ostream& os, sctp_notification* n);

std::string timestamp();

void timestamp(std::ostream&);


#endif // SCTPCAT_UTIL_HPP
