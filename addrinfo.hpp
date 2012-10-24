#ifndef ADDRINFO_HPP
#define ADDRINFO_HPP

#include <netdb.h>
#include <string>
#include <boost/shared_ptr.hpp>

boost::shared_ptr<addrinfo> getAi(int ai_family, const std::string &port, const std::string& host, bool doListen);

boost::shared_ptr<addrinfo> getAnyAddr(int ai_family);

#endif // ADDRINFO_HPP
