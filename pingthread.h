#ifndef PINGTHREAD_H
#define PINGTHREAD_H

#include "isctpsink.h"
#include <boost/thread.hpp>

class PingThread
{
public:
    PingThread(ISctpSink& sink, int bytes, int interval);

    void start();
private:
    void loop();

    ISctpSink& m_sink;
    int m_bytes;
    int m_interval;
    boost::thread m_thread;
};

#endif // PINGTHREAD_H
