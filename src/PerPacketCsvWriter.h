#ifndef MINIMALPSFPATTACKML_PERPACKETCSVWRITER_H
#define MINIMALPSFPATTACKML_PERPACKETCSVWRITER_H

#include "CsvWriter.h"
#include <deque>
#include <unordered_map>

struct PrevStreamsBuffer {
    std::deque<std::string> buf; // most recent at back
    void push(const std::string& s) {
        buf.push_back(s);
        if (buf.size() > 3) buf.pop_front();
    }
    std::string prev1() const { return buf.size()>=1? buf[buf.size()-1] : ""; }
    std::string prev2() const { return buf.size()>=2? buf[buf.size()-2] : ""; }
    std::string prev3() const { return buf.size()>=3? buf[buf.size()-3] : ""; }
};

class PerPacketCsvWriter {
public:
    CsvWriter writer;
    std::unordered_map<std::string,double> lastTsByKey;
    std::unordered_map<std::string,PrevStreamsBuffer> prevStreamsByKey;

    explicit PerPacketCsvWriter(const std::string& path): writer(path) {}

    void writeHeader() {
        writer.setHeader({
            "run","repetition","config","node","port","module","name",
            "ts","dt","stream_id","prev1","prev2","prev3",
            "src_mac","dst_mac","len_bytes","tree_id","rx_ok"
        });
    }
};

#endif


