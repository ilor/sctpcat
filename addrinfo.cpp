#include "addrinfo.hpp"
#include "exception.hpp"
#include <iostream>

namespace
{
void addrinfoDeleter(addrinfo* ptr)
{
    if (ptr)
    {
        freeaddrinfo(ptr);
    }
}
}

boost::shared_ptr<addrinfo> getAi(int aiFamily, const std::string &port, const std::string& host, bool doListen)
{
    addrinfo* res = NULL;
    addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = aiFamily;
    if (doListen)
    {
        hint.ai_flags = AI_PASSIVE;
    }
    std::cout << "getaddrinfo " <<  host << " : " << port << "\n";
    if (getaddrinfo(host.empty() ? NULL : host.c_str(),
                    port.empty() ? NULL : port.c_str(), &hint, &res) == -1)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("getaddrinfo", errno);
    }
    if (!res)
    {
        SCTPCAT_THROW(SctpCatError()) << clib_failure("getaddrinfo", errno);
    }
    std::cerr << "family " << res->ai_family << "\n";
    std::cerr << "next is " << (void*) res->ai_next << "\n";
    boost::shared_ptr<addrinfo> ai(res, addrinfoDeleter);
    return ai;
}
