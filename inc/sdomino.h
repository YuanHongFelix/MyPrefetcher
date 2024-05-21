#include <stdio.h>
#include "cache.h"
#include <map>
#include <set>
#include <cassert>
#include <set>
#define DEGREE 4

using namespace std;

// #define HYBRID

struct EIT_Entry
{
public:
    map<uint64_t, uint64_t> address_pointer_pair;
    map<uint64_t, uint64_t> access_time;
    uint64_t timer;
    uint64_t most_recent_addr;

    EIT_Entry()
    {
        timer = 0;
        most_recent_addr = 0;
        address_pointer_pair.clear();
        access_time.clear();
    }

    uint64_t get_ghb_pointer(uint64_t curr_addr)
    {
        if (address_pointer_pair.find(curr_addr) != address_pointer_pair.end())
            return address_pointer_pair[curr_addr];

        assert(address_pointer_pair.find(most_recent_addr) != address_pointer_pair.end());
        return address_pointer_pair[most_recent_addr];
    }

    void remove_oldest()
    {
        uint64_t oldest = timer + 1;
        uint64_t replace_addr;
        for (map<uint64_t, uint64_t>::iterator it = access_time.begin(); it != access_time.end(); it++)
        {
            if (it->second < oldest)
            {
                oldest = it->second;
                replace_addr = it->first;
            }
        }
        assert(oldest < (timer + 1));
        assert(address_pointer_pair.find(replace_addr) != address_pointer_pair.end());
        address_pointer_pair.erase(replace_addr);
        access_time.erase(replace_addr);
    }

    void update(uint64_t curr_addr, uint64_t pointer)
    {
        timer++;
#ifdef EIT_ENTRY_LIMIT
        if (address_pointer_pair.find(curr_addr) == address_pointer_pair.end())
            if (address_pointer_pair.size() >= 3)
                remove_oldest();

        assert(address_pointer_pair.size() <= 3);
        assert(access_time.size() <= 3);
#endif
        address_pointer_pair[curr_addr] = pointer;
        access_time[curr_addr] = timer;
        most_recent_addr = curr_addr;
    }
};

class sdomino : public Prefetcher
{
    vector<uint64_t> GHB;
    map<uint64_t, EIT_Entry> index_table;
    uint64_t last_address;

    void domino_train(uint64_t curr_addr, uint64_t last_addr)
    {
        GHB.push_back(curr_addr);
        assert(GHB.size() >= 1);

        index_table[last_addr].update(curr_addr, (GHB.size() - 1));
    }

    vector<uint64_t> domino_predict(uint64_t curr_addr, uint64_t last_addr)
    {
        vector<uint64_t> candidates;
        candidates.clear();

        if (index_table.find(last_addr) != index_table.end())
        {
            uint64_t index = index_table[last_addr].get_ghb_pointer(curr_addr);

            for (unsigned int i = 1; i <= 32; i++)
            {
                if ((index + i) >= GHB.size())
                    break;
                uint64_t candidate_phy_addr = GHB[index + i];
                candidates.push_back(candidate_phy_addr);
            }
        }
        else
            no_prediction++;

        return candidates;
    }

public:
    sdomino(string type, CACHE *cache);
    void invoke_prefetcher(uint64_t ip, uint64_t addr, uint8_t cache_hit, uint8_t type, vector<uint64_t> &pref_addr);
    void register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr);
    void dump_stats();
    void print_config() {};

    unsigned int total_access;
    unsigned int predictions;
    unsigned int no_prediction;
    uint64_t addr_context[2];
    uint64_t pointer;

    CACHE *parent = NULL;
};
