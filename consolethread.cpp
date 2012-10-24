#include "consolethread.h"
#include <iostream>

void consoleThread(ISctpSink& sink)
{
    for (;;)
    {
        std::string input;
        std::getline(std::cin, input);
        if (!input.empty())
        {
            sink.send(input.c_str(), input.size());
        }
    }
}
