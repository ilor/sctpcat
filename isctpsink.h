#ifndef ISCTPSINK_H
#define ISCTPSINK_H

#include <memory>

class ISctpSink
{
public:
    virtual void send(const char* buf, size_t len) = 0;
};

#endif // ISCTPSINK_H
