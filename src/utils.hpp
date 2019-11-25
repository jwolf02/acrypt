#ifndef __UTILS_HPP
#define __UTILS_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>

static inline bool starts_with(const std::string &a, const std::string &b) {
    return a.size() >= b.size() ? std::equal(a.begin(), a.begin() + b.size(), b.begin()) : false;
}

static inline std::vector<std::string> split(const std::string &str, const std::string &delim=" ") {
    std::vector<std::string> tokens;
    size_t last = 0;
    size_t next = 0;
    while ((next = str.find(delim, last)) != std::string::npos) {
        tokens.emplace_back(str.substr(last, next - last));
        last = next + 1;
    }
    tokens.emplace_back(str.substr(last));
    return tokens;
}

template <typename T>
inline T strto(const std::string &str) {
    static_assert(std::is_fundamental<T>::value && (std::is_arithmetic<T>::value || std::is_same<T, bool>::value),
                  "cannot convert string to non-arithmetic type");

    // signed types
    if (std::is_same<T, char>::value || std::is_same<T, short>::value || std::is_same<T, int>::value ||
        std::is_same<T, long>::value || std::is_same<T, long long>::value) {
        return (T) strtoll(str.c_str(), nullptr, 10);
    } // unsigned types
    else if (std::is_same<T, unsigned char>::value || std::is_same<T, unsigned short>::value || std::is_same<T, unsigned int>::value ||
             std::is_same<T, unsigned long>::value || std::is_same<T, unsigned long long>::value) {
        return (T) strtoull(str.c_str(), nullptr, 10);
    } // double
    else if (std::is_same<T, double>::value) {
        return strtod(str.c_str(), nullptr);
    } // float
    else if (std::is_same<T, float>::value) {
        return strtof(str.c_str(), nullptr);
    } // long double
    else if (std::is_same<T, long double>::value) {
        return strtold(str.c_str(), nullptr);
    } // bool
    else if (std::is_same<T, bool>::value) {
        return str == "true" || str == "1" || str == "True" || str == "TRUE";
    }
    else {
        throw std::domain_error("cannot convert string to specified type");
    }
}

#endif // __UTILS_HPP
