#ifndef __TIMECONVERTER_H__
#define __TIMECONVERTER_H__
#pragma once

#include "chrono"
#include "time.h"
using namespace pcpp;
using namespace std::chrono;

class TimeConverter
{
private:
public:
    timespec timestamp2timespec(const std::string ts)
    {
        /* Standard UTC Format*/
        static const std::string dateTimeFormat{"%Y-%m-%dT%H:%M:%SZ"};
        timespec result;
        std::stringstream ss{ts};
        std::tm dt;

        ss >> std::get_time(&dt, dateTimeFormat.c_str());
        if (ss.fail())
        {
            result.tv_sec = -1;
            result.tv_nsec = -1;
        }
        else
        {
            result.tv_sec = mktime(&dt);
            result.tv_nsec = 0;
        }
        return result;
    }

    timespec getcurrent_timestamp()
    {
        timespec now;
        int retval = clock_gettime(CLOCK_REALTIME, &now);
        return now;
    }

    std::string utc_system_timestamp(timespec inputtime)
    {
        char buf[64];
        std::string result;

        const int bufsize = 31;
        const int tmpsize = 21;
        tm tm;
        gmtime_r(&inputtime.tv_sec, &tm);
        strftime(buf, tmpsize, "%Y-%m-%dT%H:%M:%S.", &tm);
        sprintf(buf + tmpsize - 1, "%09luZ", inputtime.tv_nsec);

        result = std::string(buf);
        return result;
    }

    std::string local_system_timestamp(timespec inputtime)
    {
        char buf[64];
        std::string result;

        const int bufsize = 31;
        const int tmpsize = 21;
        tm tm;
        localtime_r(&inputtime.tv_sec, &tm);
        strftime(buf, tmpsize, "%Y-%m-%dT%H:%M:%S.", &tm);
        sprintf(buf + tmpsize - 1, "%09luZ", inputtime.tv_nsec);

        result = std::string(buf);
        return result;
    }

    nanoseconds timespecToDuration(timespec ts)
    {
        auto duration = seconds{ts.tv_sec} + nanoseconds{ts.tv_nsec};

        return duration_cast<std::chrono::nanoseconds>(duration);
    }

    timespec durationToTimespec(nanoseconds dur)
    {
        auto secs = duration_cast<seconds>(dur);
        dur -= secs;
        return timespec{secs.count(), dur.count()};
    }
};

#endif /* __TIMECONVERTER_H__ */