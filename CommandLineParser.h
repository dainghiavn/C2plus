#ifndef COMMAND_LINE_PARSER_H
#define COMMAND_LINE_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>

class CommandLineParser {
public:
    CommandLineParser(int argc, char* argv[]);

    bool HasOption(const std::string& name) const;
    std::string GetOption(const std::string& name, const std::string& defaultValue = "") const;

    void PrintHelp() const;

private:
    std::unordered_map<std::string, std::string> options;
    void Parse(int argc, char* argv[]);
};

#endif // COMMAND_LINE_PARSER_H
