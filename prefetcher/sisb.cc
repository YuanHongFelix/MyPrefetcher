#include "cache.h"
#include "sisb.h"
#define DEGREE 2
// #define DEGREE 4
#include <iostream>
#include <fstream>

void sisb::invoke_prefetcher(uint64_t ip, uint64_t addr, uint8_t cache_hit, uint8_t type, vector<uint64_t> &pref_addr)
{
    uint64_t sisb_candidates_out;
    vector<uint64_t> sisb_candidates;
    sisb_prefetcher_operate(addr, ip, cache_hit, type, DEGREE, sisb_candidates);
    for (uint32_t i = 0; i < sisb_candidates.size(); i++)
    {
        // parent->prefetch_line(ip, addr, sisb_candidates[i], FILL_L2, 0);
        pref_addr.emplace_back(sisb_candidates[i]);
        sisb_candidates_out = sisb_candidates[i];
    }
    return;
}

void sisb::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr)
{
    sisb_prefetcher_cache_fill(addr, set, way, prefetch, evicted_addr);
    return;
}

void sisb::dump_stats()
{
    sisb_prefetcher_final_stats();
}

sisb::sisb(string type, CACHE *cache) : Prefetcher(type), parent(cache)
{
    sisb_prefetcher_initialize();
}
