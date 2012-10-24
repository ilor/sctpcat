#include "pingthread.h"
#include <boost/thread.hpp>

PingThread::PingThread(ISctpSink& sink, int bytes, int interval)
    : m_sink(sink), m_bytes(bytes), m_interval(interval)
{
}

void PingThread::start()
{
    m_thread = boost::thread(boost::bind(&PingThread::loop, this));
}

void PingThread::loop()
{
    std::vector<char> buf(m_bytes);
    for (int i = 0; i < m_bytes; ++i)
    {
        buf[i] = 'A' + (i % ('Z' - 'A'));
    }
    for (;;)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(m_interval));
        m_sink.send(&buf[0], m_bytes);
    }
}
