#ifndef LIBCPPTLS_TLS_GENRAND_H
#define LIBCPPTLS_TLS_GENRAND_H

#include <cstdint>
#include <random>
#include <vector>

template <template <typename> typename DIS_T = std::uniform_int_distribution>
std::vector<uint8_t> genRand(size_t len)
{
    std::vector<uint8_t> ret;
    std::random_device rd;
    std::mt19937 gen(rd());
    DIS_T<uint8_t> dis(0, UINT8_MAX);

    for (size_t i = 0; i < len; ++i) {
        ret.push_back(dis(gen));
    }
    return ret;
}

template <template <typename> typename DIS_T = std::uniform_int_distribution, typename RES_T = int>
RES_T randInt(RES_T max, RES_T min = 0)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    DIS_T<RES_T> dis(0, UINT8_MAX);
    return dis(gen);
}

template <template <typename> typename DIS_T = std::uniform_int_distribution, typename ITER_T>
void fillRand(std::vector<uint8_t> &v, ITER_T &&beg, ITER_T &&end)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    DIS_T<uint8_t> dis(0, UINT8_MAX);

    for (auto it = beg; it != end; ++it) {
        *it = dis(gen);
    }
}

#endif
