// Simple CSV writer used by DataCollector and per-packet logger
#ifndef MINIMALPSFPATTACKML_CSVWRITER_H
#define MINIMALPSFPATTACKML_CSVWRITER_H

#include <fstream>
#include <string>
#include <vector>
#include <sstream>

class CsvWriter {
public:
    explicit CsvWriter(const std::string& path): stream(), headerWritten(false) {
        // Ensure parent directory exists before opening file
        openWithDirs(path);
    }

    bool good() const { return stream.good(); }

    void setHeader(const std::vector<std::string>& cols) { headerColumns = cols; }
    void newRow() { rowBuffer.clear(); rowBuffer.reserve(headerColumns.size()); }
    void add(const std::string& s) { rowBuffer.push_back(s); }
    void add(const char* s) { rowBuffer.emplace_back(s ? s : ""); }
    void add(int v) { rowBuffer.push_back(std::to_string(v)); }
    void add(long v) { rowBuffer.push_back(std::to_string(v)); }
    void add(double v) { rowBuffer.push_back(doubleToString(v)); }

    void writeToFile() {
        if (!stream.is_open()) return;
        if (!headerWritten && !headerColumns.empty()) {
            writeLine(headerColumns);
            headerWritten = true;
        }
        writeLine(rowBuffer);
    }

    void flush() { if (stream.is_open()) stream.flush(); }

private:
    std::ofstream stream;
    bool headerWritten {false};
    std::vector<std::string> headerColumns;
    std::vector<std::string> rowBuffer;

    static std::string doubleToString(double v) {
        std::ostringstream oss; oss.setf(std::ios::fixed, std::ios::floatfield); oss.precision(9); oss << v; return oss.str();
    }
    static std::string escape(const std::string& s) {
        bool needQuotes = false; for (char c: s) { if (c=='"' || c==',' || c=='\n' || c=='\r') { needQuotes = true; break; } }
        if (!needQuotes && !s.empty() && s.find_first_of(' ') == std::string::npos) return s;
        std::string out = "\""; for (char c: s) { if (c=='"') out += '"'; out += c; } out += '"'; return out;
    }
    void writeLine(const std::vector<std::string>& fields) {
        for (size_t i=0;i<fields.size();++i) { if (i) stream << ','; stream << escape(fields[i]); } stream << '\n';
    }

    static bool ensureDir(const std::string& path) {
        // crude: create directory portion if path contains '/'
        auto pos = path.find_last_of('/');
        if (pos == std::string::npos) return true;
        std::string dir = path.substr(0, pos);
        if (dir.empty()) return true;
        // portable mkdir -p using system; acceptable in sim context
        std::string cmd = std::string("mkdir -p ") + dir;
        int rc = system(cmd.c_str());
        (void)rc; // ignore errors
        return true;
    }
    void openWithDirs(const std::string& path) {
        ensureDir(path);
        stream.open(path, std::ios::out);
    }
};

#endif

