#include "cache.h"
#include "sdomino.h"

sdomino::sdomino(string type, CACHE *cache) : Prefetcher(type), parent(cache)
{
    last_address = 0;
    GHB.clear();
    index_table.clear();

    total_access = 0;
    predictions = 0;
    no_prediction = 0;
}

void sdomino::invoke_prefetcher(uint64_t ip, uint64_t addr, uint8_t cache_hit, uint8_t type, vector<uint64_t> &pref_addr)
{
    if (type != LOAD)
        return;

    //    if(cache_hit)
    //        return metadata_in;

    uint64_t addr_B = (addr >> 6) << 6;

    if (addr_B == last_address)
        return;

    total_access++;

    // Predict before training
    vector<uint64_t> candidates = domino_predict(addr_B, last_address);

    int num_prefetched = 0;
    uint64_t candidates_out;
    for (unsigned int i = 0; i < candidates.size(); i++)
    {
        candidates_out = candidates[i];
        pref_addr.emplace_back(candidates[i]);
        // int ret = parent->prefetch_line(ip, addr, candidates[i], FILL_L2, 0);
        // if (ret == 1)
        //{
        predictions++;
        num_prefetched++;

        //}
        if (num_prefetched >= DEGREE)
            break;
    }

    domino_train(addr_B, last_address);

    last_address = addr_B;

    return;
}

void sdomino::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr)
{
}

void sdomino::dump_stats()
{
}
