#ifndef __FILEEXTRACT_H__
#define __FILEEXTRACT_H__
#pragma once

#include <Logger.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapPlusPlusVersion.h>
#include <RawPacket.h>
#include <SystemUtils.h>
#include <dirent.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <sys/stat.h>
#include <vector>

#include "Common.h"
#include "Timeconverter.h"

#define DIR_SEPARATOR "/"

#define ERROR_STRING_LEN 500
char errorString[ERROR_STRING_LEN];
#define MAX_RECEIVE_BURST 64

using namespace pcpp;

class FileExtract
{
private:
    /**
     * Searches all packet in a given pcap file for a certain search criteria. Returns how many packets matched the seatch criteria
     */
    int searchPcap(std::string begin_t, std::string end_t, std::string pcapFilePath, std::string searchCriteria,
                   std::ofstream *detailedReportFile,
                   pcpp::PcapFileWriterDevice *pcapOutWriter)
    {

        // create the pcap/pcap-ng reader
        IFileReaderDevice *reader = IFileReaderDevice::getReader(pcapFilePath);

        // if the reader fails to open
        if (!reader->open())
        {
            if (detailedReportFile != NULL)
            {
                // PcapPlusPlus writes the error to the error string variable we set it to write to
                // write this error to the report file
                (*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
                (*detailedReportFile) << "    ";
                std::string errorStr = errorString;
                (*detailedReportFile) << errorStr << std::endl;
            }

            // free the reader memory and return
            delete reader;
            return 0;
        }

        // set the filter for the file so only packets that match the search criteria will be read
        if (!reader->setFilter(searchCriteria))
        {
            // free the reader memory and return
            delete reader;
            return 0;
        }

        if (detailedReportFile != NULL)
        {
            (*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
        }

        time_t b = getInputTimeFromParam(begin_t).tv_sec;
        time_t e = getInputTimeFromParam(end_t).tv_sec;

        int packetCount = 0;
        RawPacket rawPacket;

        // read packets from the file. Since we already set the filter, only packets that matches the filter will be read
        while (reader->getNextPacket(rawPacket))
        {
            // parse the packet
            Packet parsedPacket(&rawPacket);

            time_t rawPkgTimestamp = parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec;

            if ((b == e) && (rawPkgTimestamp != b))
            {
                continue;
            }

            // if a detailed report is required, parse the packet and print it to the report file
            if (detailedReportFile != NULL)
            {
                // print layer by layer by layer as we want to add a few spaces before each layer
                std::vector<std::string> packetLayers;

                parsedPacket.toStringList(packetLayers);

                for (std::vector<std::string>::iterator iter = packetLayers.begin(); iter != packetLayers.end(); iter++)
                {
                    (*detailedReportFile) << "\n    " << (*iter);
                }

                (*detailedReportFile) << std::endl;
            }

            // write the packet to the output file pcap
            if (pcapOutWriter != NULL)
            {
                RawPacket *pkg_p = parsedPacket.getRawPacket();
                // printf("write to pcap\n");
                pcapOutWriter->writePacket(*pkg_p);
            }
            // else
            // {
            //     printf("could not open pcap file output\n");
            // }

            // TimeConverter timconvert;
            // printf("rawPacket.getPacketTimeStamp: %ld\n", rawPacket.getPacketTimeStamp());
            // printf("timconvert to local time: %s\n", timconvert.local_system_timestamp(rawPacket.getPacketTimeStamp()).c_str());
            // count the packet read
            packetCount++;
        }

        // close the reader file
        reader->close();

        // finalize the report
        if (detailedReportFile != NULL)
        {
            if (packetCount > 0)
                (*detailedReportFile) << "\n";

            (*detailedReportFile) << "    ----> Found " << packetCount << " packets" << std::endl
                                  << std::endl;
        }

        // free the reader memory
        delete reader;

        // return how many packets matched the search criteria
        return packetCount;
    }

    /*
    * Returns the extension of a given file name
    */
    std::string getExtension(std::string fileName)
    {
        return fileName.substr(fileName.find_last_of(".") + 1);
    }

    timespec getInputTimeFromParam(std::string input_time)
    {
        timespec result = timespec{.tv_sec = -1, .tv_nsec = -1};

        if (input_time == "")
        {
            return timespec{.tv_sec = 0, .tv_nsec = 0};
        }

        /* Standard UTC Format*/
        static const std::string dateTimeFormat{"%Y-%m-%d %H:%M:%SZ"};
        // timespec result;
        std::stringstream ss{input_time};
        std::tm dt;

        ss >> std::get_time(&dt, dateTimeFormat.c_str());
        if (ss.fail())
        {
            return result;
            // EXIT_WITH_ERROR("input time wrong format");
        }
        else
        {
            result.tv_sec = mktime(&dt);
            result.tv_nsec = 0;
            return result;
        }
    }

    static timespec gettimestampfrom(std::string name)
    {
        timespec result;
        std::string timestamp = name.substr(name.find_last_of("_") + 1);
        // printf("timestamp : %s\n", timestamp.c_str());
        stringstream stream(timestamp);
        string timestampAsString;
        // break comma-separated string into string list
        int i = 0;
        while (getline(stream, timestampAsString, '.'))
        {
            std::stringstream stream2(timestampAsString);
            if (i == 0)
            {
                result.tv_nsec = std::stol(timestampAsString);
            }
            else if (i == 1)
            {
                result.tv_sec = std::stol(timestampAsString);
            }

            i++;
        }
        // printf("result >>>> sec: %ld nsec: %ld\n", result.tv_sec, result.tv_nsec);
        return result;
    }

    static bool sortbyTime(std::string i, std::string j)
    {
        timespec n = gettimestampfrom(i);
        timespec m = gettimestampfrom(j);

        if (n.tv_sec == m.tv_sec)
        {
            return (i < j);
        };
        return n.tv_sec < m.tv_sec;
    }

    std::vector<int> searchFile(std::string begin_t, std::string end_t, std::vector<std::string> pcaplist)
    {
        std::vector<int> idx_file;
        timespec timestamp;
        TimeConverter timconvert;

        time_t b = getInputTimeFromParam(begin_t).tv_sec;
        time_t e = getInputTimeFromParam(end_t).tv_sec;
        // time_t inputDur = e - b;

        if ((b == 0) || (e == 0))
        {
            return idx_file;
        }

        // printf("begin_t string >>> %s\n", timconvert.local_system_timestamp(getInputTimeFromParam(begin_t)).c_str());
        // printf("begin_t timespec >>> %ld\n", getInputTimeFromParam(begin_t).tv_sec);
        // printf("end_t string   >>> %s\n", timconvert.local_system_timestamp(getInputTimeFromParam(end_t)).c_str());
        // printf("end_t timespec >>> %ld\n", getInputTimeFromParam(end_t).tv_sec);
        int idx = 0;
        bool found_b = false;
        for (int i = 0; i < pcaplist.size(); i++)
        {

            std::string fileName = pcaplist[i];
            // time_t filesDur = getDurationFiles(pcaplist[i], pcaplist[i + 1]);
            timestamp = gettimestampfrom(fileName.substr(fileName.find_last_of("/") + 1));
            // printf("timestamp >>> Sec %ld : nSec : %ld\n", timestamp.tv_sec, timestamp.tv_nsec);
            // printf("timestamp string at %d >>> %s\n", i, timconvert.local_system_timestamp(timestamp).c_str());
            if ((!found_b) && (timestamp.tv_sec >= b))
            {
                idx = i - 1;
                found_b = true;
                // printf("************************** Found begin at index : %d/%d **************************\n", i, pcaplist.size());
                // printf("begin input >>> Sec : %ld\n", b);
                // printf("End at index-1 >>> %d >> Sec : %ld\n", idx, gettimestampfrom(pcaplist[i - 1].substr(fileName.find_last_of("/") + 1)).tv_sec);
                // printf("begin at index   >>> %d >> Sec : %ld\n", i, gettimestampfrom(pcaplist[i].substr(fileName.find_last_of("/") + 1)).tv_sec);
            }

            if (found_b)
            {
                idx_file.push_back(idx);
                idx++;
                if (timestamp.tv_sec >= e)
                {
                    // printf("************************** Found End at index : %d/%d **************************\n", i, pcaplist.size());
                    // printf("End input >>> Sec : %ld\n", e);
                    // printf("End at index-1 >>> %d >> Sec : %ld\n", idx, gettimestampfrom(pcaplist[i - 1].substr(fileName.find_last_of("/") + 1)).tv_sec);
                    // printf("End at index   >>> %d >> Sec : %ld\n", i, gettimestampfrom(pcaplist[i].substr(fileName.find_last_of("/") + 1)).tv_sec);
                    found_b = false;

                    if ((find(idx_file.begin(), idx_file.end(), i) == idx_file.end()))
                    {
                        // printf("idx_file.push_back(%d);\n", i);
                        idx_file.push_back(i);
                    }
                    break;
                }
            }
        }

        // for (int i = 0; i < idx_file.size(); i++)
        // {
        //     printf("idx_file >>>  %d\n", idx_file[i]);
        // }

        // EXIT_WITH_ERROR("debuging finding begin");
        // sort(idx_file.begin(), idx_file.end());

        return idx_file;
    }

    void searchDirectories(std::string core, std::map<std::string, bool> extensionsToSearch,
                           struct PcapFileParamData *pcappramdata,
                           pcpp::PcapFileWriterDevice *pcapOutWriter)
    {
        std::string directory = pcappramdata->path;
        // open the directory
        DIR *dir = opendir(directory.c_str());

        // dir is null usually when user has no access permissions
        if (dir == NULL)
            return;

        struct dirent *entry = readdir(dir);

        std::vector<std::string> pcapList;

        // go over all files in this directory
        while (entry != NULL)
        {
            std::string name(entry->d_name);

            // construct directory full path
            std::string dirPath = directory;
            std::string dirSep = DIR_SEPARATOR;
            if (0 != directory.compare(directory.length() - dirSep.length(), dirSep.length(), dirSep))
            {
                dirPath += DIR_SEPARATOR;
            }

            dirPath += name;

            struct stat info;

            // get file attributes
            if (stat(dirPath.c_str(), &info) != 0)
            {
                entry = readdir(dir);
                continue;
            }

            // if the file is not a directory
            if (!(info.st_mode & S_IFDIR))
            {
                // check if the file extension matches the requested extensions to search. If it does, put the file name in a list of files
                // that should be searched (don't do the search just yet)
                if ((extensionsToSearch.find(getExtension(name)) != extensionsToSearch.end()) &&
                    (name.find(core) != string::npos))
                {
                    pcapList.push_back(dirPath);
                }

                entry = readdir(dir);
                continue;
            }

            // if the file is a '.' or '..' skip it
            if (name == "." || name == "..")
            {
                entry = readdir(dir);
                continue;
            }

            // if we got to here it means the file is actually a directory. If required to search sub-directories, call this method recursively to search
            // inside this sub-directory
            // if (includeSubDirectories)
            // searchDirectories(dirPath, true, searchCriteria, detailedReportFile, extensionsToSearch, totalDirSearched, totalFilesSearched, totalPacketsFound);

            // move to the next file
            entry = readdir(dir);
        }

        // close dir
        closedir(dir);

        sort(pcapList.begin(), pcapList.end(), sortbyTime);

        std::vector<int> idx_pcap = searchFile(pcappramdata->begin_t, pcappramdata->end_t, pcapList);

        for (int i = 0; i < idx_pcap.size(); i++)
        {
            timespec timestamp;
            TimeConverter timconvert;
            // printf("%d, \n", idx_pcap[i]);
            std::string fileName = pcapList[idx_pcap[i]];
            // timestamp = gettimestampfrom(fileName.substr(fileName.find_last_of("/") + 1));
            // printf("timestamp string >>> %s\n", timconvert.local_system_timestamp(timestamp).c_str());
            // do the actual search
            // printf("fileName string >>> %s\n", fileName.c_str());

            int packetsFound = searchPcap(pcappramdata->begin_t, pcappramdata->end_t,
                                          fileName, pcappramdata->searchCriteria,
                                          pcappramdata->detailedReportFile, pcapOutWriter);

            if (packetsFound > 0)
            {
                printf("%d packets found in '%s'\n", packetsFound, fileName.c_str());

                // printf("pcapfiles >>> %s\n", fileName.substr(fileName.find_last_of("/") + 1).c_str());
            }
        }

        // if (pcapOutWriter != NULL)
        // {
        //     delete pcapOutWriter;
        // }
    }

public:
    bool checkTimeformat(std::string tim)
    {
        time_t tmp = getInputTimeFromParam(tim).tv_sec;
        if (tmp > 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    int PcapExtractEngine(PcapFileParamData *pcappramdata)
    {

        pcpp::PcapFileWriterDevice *pcapWriter = NULL;
        std::map<std::string, bool> extensionsToSearch;
        extensionsToSearch["pcap"] = true;
        string outputfilename;

        if (pcappramdata == NULL)
        {
            EXIT_WITH_ERROR("Couldn't find parameter Pcapfile Input");
        }

        if (pcappramdata->outputFileName != "")
        {
            outputfilename = pcappramdata->outputFileName;
            // printf("outputfile %s\n", outputfilename.c_str());
            pcapWriter = new pcpp::PcapFileWriterDevice(outputfilename);
            if (!pcapWriter->open())
            {
                EXIT_WITH_ERROR("Couldn't open pcap writer output");
            }
        }

        // printf("PathToWritePackets: %s\n", pcappramdata->path.c_str());

        searchDirectories("Core1", extensionsToSearch,
                          pcappramdata,
                          pcapWriter);

        if (pcapWriter != NULL)
        {
            printf("close and delete pcap file writer\n");
            delete pcapWriter;
        }
    }
};

#endif /* __FILEEXTRACT_H__ */