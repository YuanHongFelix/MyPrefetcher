#ifndef PMP_H
#define PMP_H

#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include "prefetcher.h"
#include "cache.h"
#include "bakshalipour_framework.h"

using namespace std;

class FTDataPMP
{
public:
    uint64_t pc;
    int offset;
};

class FTPMP : public LRUSetAssociativeCache<FTDataPMP>
{
    typedef LRUSetAssociativeCache<FTDataPMP> Super;

public:
    FTPMP(int size, int debug_level = 0, int num_ways = 8) : Super(size, num_ways, debug_level)
    {
        // assert(__builtin_popcount(size) == 1);
        if (this->debug_level >= 1)
            cerr << "FT::FT(size=" << size << ", debug_level=" << debug_level
                 << ", num_ways=" << num_ways << ")" << dec << endl;
    }

    Entry *find(uint64_t region_number)
    {
        if (this->debug_level >= 2)
            cerr << "FT::find(region_number=0x" << hex << region_number << ")" << dec << endl;
        uint64_t key = this->build_key(region_number);
        Entry *entry = Super::find(key);
        if (!entry)
        {
            if (this->debug_level >= 2)
                cerr << "[FT::find] Miss!" << dec << endl;
            return nullptr;
        }
        if (this->debug_level >= 2)
            cerr << "[FT::find] Hit!" << dec << endl;
        Super::set_mru(key);
        return entry;
    }

    void insert(uint64_t region_number, uint64_t pc, int offset)
    {
        if (this->debug_level >= 2)
            cerr << "FT::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
                 << ", offset=" << dec << offset << ")" << dec << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        Super::insert(key, {pc, offset});
        Super::set_mru(key);
    }

    Entry *erase(uint64_t region_number)
    {
        uint64_t key = this->build_key(region_number);
        return Super::erase(key);
    }

    string log()
    {
        vector<string> headers({"Region", "PC", "Offset"});
        return Super::log(headers);
    }

private:
    /* @override */
    void write_data(Entry &entry, Table &table, int row)
    {
        uint64_t key = hash_index(entry.key, this->index_len);
        table.set_cell(row, 0, key);
        table.set_cell(row, 1, entry.data.pc);
        table.set_cell(row, 2, entry.data.offset);
    }

    uint64_t build_key(uint64_t region_number)
    {
        uint64_t key = region_number & ((1ULL << 36) - 1);
        return hash_index(key, this->index_len);
    }

    /*==========================================================*/
    /* Entry   = [tag, offset, PC, valid, LRU]                  */
    /* Storage = size * (37 - lg(sets) + 5 + 16 + 1 + lg(ways)) */
    /* 64 * (37 - lg(4) + 5 + 16 + 1 + lg(16)) = 488 Bytes      */
    /*==========================================================*/
};

template <class T>
string pmp_pattern_to_string(const vector<T> &pattern)
{
    ostringstream oss;
    for (unsigned i = 0; i < pattern.size(); i += 1)
        oss << int(pattern[i]);
    return oss.str();
}

class ATDataPMP
{
public:
    uint64_t pc;
    int offset;
    vector<bool> pattern;
};

class ATPMP : public LRUSetAssociativeCache<ATDataPMP>
{
    typedef LRUSetAssociativeCache<ATDataPMP> Super;

public:
    ATPMP(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len)
    {
        // assert(__builtin_popcount(size) == 1);
        // assert(__builtin_popcount(pattern_len) == 1);
        if (this->debug_level >= 1)
            cerr << "AccumulationTable::AccumulationTable(size=" << size << ", pattern_len=" << pattern_len
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
    }

    /**
     * @return False if the tag wasn't found and true if the pattern bit was successfully set
     */
    bool set_pattern(uint64_t region_number, int offset)
    {
        if (this->debug_level >= 2)
            cerr << "AccumulationTable::set_pattern(region_number=0x" << hex << region_number << ", offset=" << dec
                 << offset << ")" << dec << endl;
        uint64_t key = this->build_key(region_number);
        Entry *entry = Super::find(key);
        if (!entry)
        {
            if (this->debug_level >= 2)
                cerr << "[AccumulationTable::set_pattern] Not found!" << dec << endl;
            return false;
        }
        entry->data.pattern[offset] = true;
        Super::set_mru(key);
        if (this->debug_level >= 2)
            cerr << "[AccumulationTable::set_pattern] OK!" << dec << endl;
        return true;
    }

    /* NOTE: `region_number` is probably truncated since it comes from the filter table */
    Entry insert(uint64_t region_number, uint64_t pc, int offset)
    {
        if (this->debug_level >= 2)
            cerr << "AccumulationTable::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
                 << ", offset=" << dec << offset << dec << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        vector<bool> pattern(this->pattern_len, false);
        pattern[offset] = true;
        Entry old_entry = Super::insert(key, {pc, offset, pattern});
        Super::set_mru(key);
        return old_entry;
    }

    Entry *erase(uint64_t region_number)
    {
        uint64_t key = this->build_key(region_number);
        return Super::erase(key);
    }

    string log()
    {
        vector<string> headers({"Region", "PC", "Offset", "Pattern"});
        return Super::log(headers);
    }

private:
    /* @override */
    void write_data(Entry &entry, Table &table, int row)
    {
        uint64_t key = hash_index(entry.key, this->index_len);
        table.set_cell(row, 0, key);
        table.set_cell(row, 1, entry.data.pc);
        table.set_cell(row, 2, entry.data.offset);
        table.set_cell(row, 3, pmp_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t region_number)
    {
        uint64_t key = region_number & ((1ULL << 36) - 1);
        return hash_index(key, this->index_len);
    }

    int pattern_len;

    /*===============================================================*/
    /* Entry   = [tag, map, offset, PC, valid, LRU]                  */
    /* Storage = size * (37 - lg(sets) + 32 + 5 + 16 + 1 + lg(ways)) */
    /* 128 * (37 - lg(8) + 32 + 5 + 16 + 1 + lg(16)) = 1472 Bytes    */
    /*===============================================================*/
};

template <class T>
vector<T> pmp_rotate(const vector<T> &x, int n)
{
    vector<T> y;
    int len = x.size();
    n = n % len;
    for (int i = 0; i < len; i += 1)
        y.push_back(x[(i - n + len) % len]);
    return y;
}

class PatternTable
{
public:
    PatternTable(int pattern_len, int counter_max, int debug_level = 0) : pattern_len(pattern_len), counter_max(counter_max), table(pattern_len, vector<int>(pattern_len, 0)), debug_level(debug_level)
    {
        if (this->debug_level >= 1)
            cerr << "PT::PT(pattern_len=" << pattern_len << ", debug_level=" << debug_level << endl;
    }
    void merge(int key, vector<bool> pattern)
    {
        key = key < 0 ? -key : key;
        if (this->debug_level >= 2)
            cerr << "PT::merge(key=" << dec << key
                 << ", pattern=" << pmp_pattern_to_string(pattern) << ")" << dec << endl;
        // assert((int)pattern.size() == this->pattern_len);
        vector<int> &old = table[key % pattern_len];
        for (size_t i = 0; i < pattern_len; i++)
        {
            if (pattern[i])
                old[i]++;
        }
        if (old[0] == counter_max)
        {
            for (size_t i = 0; i < pattern_len; i++)
            {
                old[i] /= 2;
            }
        }
    }

    vector<int> extrate(int key)
    {
        key = key < 0 ? -key : key;
        if (this->debug_level >= 2)
            cerr << "PT::extrate(key=" << dec << key << endl;
        vector<int> old = table[key % pattern_len];
        if (!old[0])
            return vector<int>();
        vector<int> result(pattern_len, 0);
        for (size_t i = 1; i < pattern_len; i++)
        {
            if (old[i] >= l1_thresh * old[0])
                result[i] = FILL_L1;
            else if (old[i] >= l2_thresh * old[0])
                result[i] = FILL_L2;
        }
        return result;
    }

private:
    int pattern_len, counter_max;
    vector<vector<int>> table;
    int debug_level = 0;
    float l1_thresh, l2_thresh;
};

class PSDataPMP
{
public:
    /* contains the prefetch fill level for each block of spatial region */
    vector<int> pattern;
};

class PSPMP : public LRUSetAssociativeCache<PSDataPMP>
{
    typedef LRUSetAssociativeCache<PSDataPMP> Super;

public:
    PSPMP(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len)
    {
        if (this->debug_level >= 1)
            cerr << "PrefetchStreamer::PrefetchStreamer(size=" << size << ", pattern_len=" << pattern_len
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
    }

    void insert(uint64_t region_number, vector<int> pattern)
    {
        if (this->debug_level >= 2)
            cerr << "PrefetchStreamer::insert(region_number=0x" << hex << region_number
                 << ", pattern=" << pmp_pattern_to_string(pattern) << ")" << dec << endl;
        uint64_t key = this->build_key(region_number);
        Super::insert(key, {pattern});
        Super::set_mru(key);
    }

    int prefetch(CACHE *cache, uint64_t block_address)
    {
        if (this->debug_level >= 2)
        {
            cerr << "PrefetchStreamer::prefetch(cache=" << cache->NAME << ", block_address=0x" << hex << block_address
                 << ")" << dec << endl;
            cerr << "[PrefetchStreamer::prefetch] " << cache->PQ.occupancy << "/" << cache->PQ.SIZE
                 << " PQ entries occupied." << dec << endl;
            cerr << "[PrefetchStreamer::prefetch] " << cache->MSHR.occupancy << "/" << cache->MSHR.SIZE
                 << " MSHR entries occupied." << dec << endl;
        }
        uint64_t base_addr = block_address << LOG2_BLOCK_SIZE;
        int region_offset = block_address % this->pattern_len;
        uint64_t region_number = block_address / this->pattern_len;
        uint64_t key = this->build_key(region_number);
        Entry *entry = Super::find(key);
        if (!entry)
        {
            if (this->debug_level >= 2)
                cerr << "[PrefetchStreamer::prefetch] No entry found." << dec << endl;
            return 0;
        }
        Super::set_mru(key);
        int pf_issued = 0;
        vector<int> &pattern = entry->data.pattern;
        pattern[region_offset] = 0; /* accessed block will be automatically fetched if necessary (miss) */
        int pf_offset;
        /* prefetch blocks that are close to the recent access first (locality!) */
        for (int d = 1; d < this->pattern_len; d += 1)
        {
            /* prefer positive strides */
            for (int sgn = +1; sgn >= -1; sgn -= 2)
            {
                pf_offset = region_offset + sgn * d;
                if (0 <= pf_offset && pf_offset < this->pattern_len && pattern[pf_offset] > 0)
                {
                    uint64_t pf_address = (region_number * this->pattern_len + pf_offset) << LOG2_BLOCK_SIZE;
                    if (cache->PQ.occupancy + cache->MSHR.occupancy < cache->MSHR.SIZE - 1 && cache->PQ.occupancy < cache->PQ.SIZE)
                    {
                        cache->prefetch_line(0, base_addr, pf_address, pattern[pf_offset], 0);
                        pf_issued += 1;
                        pattern[pf_offset] = 0;
                    }
                    else
                    {
                        /* prefetching limit is reached */
                        return pf_issued;
                    }
                }
            }
        }
        /* all prefetches done for this spatial region */
        Super::erase(key);
        return pf_issued;
    }

    string log()
    {
        vector<string> headers({"Region", "Pattern"});
        return Super::log(headers);
    }

private:
    /* @override */
    void write_data(Entry &entry, Table &table, int row)
    {
        uint64_t key = hash_index(entry.key, this->index_len);
        table.set_cell(row, 0, key);
        table.set_cell(row, 1, pmp_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t region_number) { return hash_index(region_number, this->index_len); }

    int pattern_len;

    /*======================================================*/
    /* Entry   = [tag, map, valid, LRU]                     */
    /* Storage = size * (53 - lg(sets) + 64 + 1 + lg(ways)) */
    /* 128 * (53 - lg(8) + 64 + 1 + lg(16)) = 1904 Bytes    */
    /*======================================================*/
};

class PMP : public Prefetcher
{
public:
    PMP(string type, CACHE *cache);
    ~PMP();
    void invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr);
    void register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr);
    void dump_stats();
    void print_config();

    /**
     * Updates PMP's state based on the most recent LOAD access.
     * @param block_number The block address of the most recent LOAD access
     * @param pc           The PC of the most recent LOAD access
     */
    void access(uint64_t block_number, uint64_t pc);
    void eviction(uint64_t block_number);
    int prefetch(uint64_t block_number);
    void set_debug_level(int debug_level);
    void log();

private:
    /**
     * Performs a PHT lookup and computes a prefetching pattern from the result.
     * @return The appropriate prefetch level for all blocks based on PHT output or an empty vector
     *         if no blocks should be prefetched
     */
    vector<int> find_in_pht(uint64_t pc, uint64_t address);

    void insert_in_pht(const ATPMP::Entry &entry);

    void init_knobs();
    void init_stats();

    /*======================*/
    CACHE *parent = NULL;
    int pattern_len;
    FTPMP ft;
    ATPMP at;
    PatternTable opt, ppt;
    PSPMP ps;
    int debug_level = 0;
};

#endif /* PMP_H */
