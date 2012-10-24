#ifndef SCTPCAT_EXCEPTION_HPP
#define SCTPCAT_EXCEPTION_HPP

#include <boost/exception/all.hpp>

typedef boost::tuple<boost::errinfo_api_function,boost::errinfo_errno> clib_failure;
typedef boost::error_info<struct tag_sa_family, sa_family_t> sa_family_info;
typedef boost::error_info<struct tag_recv_error_info, const char*> recv_error_info;

struct SctpCatError : virtual boost::exception, virtual std::exception {};
struct SctpReceiveError : virtual SctpCatError {};

#define SCTPCAT_THROW(e) \
    throw (e) << ::boost::throw_function(BOOST_CURRENT_FUNCTION) <<\
        ::boost::throw_file(__FILE__) <<\
        ::boost::throw_line((int)__LINE__)

#endif // SCTPCAT_EXCEPTION_HPP
