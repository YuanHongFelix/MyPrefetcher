#ifndef RSA_H
#define RSA_H

// #define SHORT_ACCUMULATION
#define ACCURACY_LEVELDOWN

#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include "prefetcher.h"
#include "cache.h"
#include "bakshalipour_framework.h"

using namespace std;

class FTData
{
public:
    uint64_t pc;
    int offset;
};

class FT : public LRUSetAssociativeCache<FTData>
{
    typedef LRUSetAssociativeCache<FTData> Super;

public:
    FT(int size, int pattern_len, int debug_level = 0, int num_ways = 16) : Super(size, num_ways, debug_level), pattern_len(pattern_len)
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

    int get_pattern_len() { return this->pattern_len; }

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
        uint64_t key = region_number & ((1ULL << (42 - __builtin_ctz(pattern_len))) - 1);
        return hash_index(key, this->index_len);
    }

    int pattern_len;

    /*==========================================================*/
    /* Entry   = [tag, offset, PC, valid, LRU]                  */
    /* Storage = size * (37 - lg(sets) + 5 + 16 + 1 + lg(ways)) */
    /* 64 * (37 - lg(4) + 5 + 16 + 1 + lg(16)) = 488 Bytes      */
    /*==========================================================*/
};

template <class T>
string rsa_pattern_to_string(const vector<T> &pattern)
{
    ostringstream oss;
    for (unsigned i = 0; i < pattern.size(); i += 1)
        oss << int(pattern[i]);
    return oss.str();
}

class ATData
{
public:
    uint64_t pc_first;
    int offset_first;
    vector<bool> pattern;
    bool is_level_up;
    uint64_t pc_second;
    int offset_second;
};

class AT : public LRUSetAssociativeCache<ATData>
{
    typedef LRUSetAssociativeCache<ATData> Super;

public:
    AT(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len)
    {
        // assert(__builtin_popcount(size) == 1);
        // assert(__builtin_popcount(pattern_len) == 1);
        if (this->debug_level >= 1)
            cerr << "AT::AT(size=" << size << ", pattern_len=" << pattern_len
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
    }

    /**
     * @return False if the tag wasn't found and true if the pattern bit was successfully set
     */
    bool set_pattern(uint64_t region_number, int offset)
    {
        if (this->debug_level >= 2)
            cerr << "AT::set_pattern(region_number=0x" << hex << region_number << ", offset=" << dec
                 << offset << ")" << dec << endl;
        uint64_t key = this->build_key(region_number);
        Entry *entry = Super::find(key);
        if (!entry)
        {
            if (this->debug_level >= 2)
                cerr << "[AT::set_pattern] Not found!" << dec << endl;
            return false;
        }
        entry->data.pattern[offset] = true;
        Super::set_mru(key);
        if (this->debug_level >= 2)
            cerr << "[AT::set_pattern] OK!" << dec << endl;
        return true;
    }

    /* NOTE: `region_number` is probably truncated since it comes from the filter table */
    Entry insert(uint64_t region_number, uint64_t pc, int offset)
    {
        if (this->debug_level >= 2)
            cerr << "AT::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
                 << ", offset=" << dec << offset << dec << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        vector<bool> pattern(this->pattern_len, false);
        pattern[offset] = true;
        Entry old_entry = Super::insert(key, {pc, offset, pattern, false, 0, 0});
#ifdef SHORT_ACCUMULATION
        event_to_region[(offset << 16) | (pc & (1 << 16 - 1))] = region_number;
#endif
        Super::set_mru(key);
        return old_entry;
    }

    Entry insert(uint64_t region_number, uint64_t pc_first, int offset_first, uint64_t pc_second, int offset_second, vector<bool> pattern)
    {
        if (this->debug_level >= 2)
            cerr << "AT::insert(region_number=0x" << hex << region_number
                 << ", pc_first=0x" << pc_first << ", offset_first=" << dec << offset_first << dec
                 << ", pc_second=0x" << pc_second << ", offset_second=" << dec << offset_second << dec
                 << ", pattern=" << rsa_pattern_to_string(pattern)
                 << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        Entry old_entry = Super::insert(key, {pc_first, offset_first, pattern, true, pc_second, offset_second});
#ifdef SHORT_ACCUMULATION
        event_to_region[(offset_first << 16) | (pc_first & (1 << 16 - 1))] = region_number;
#endif
        Super::set_mru(key);
        return old_entry;
    }

    Entry *erase(uint64_t region_number)
    {
        uint64_t key = this->build_key(region_number);
#ifdef SHORT_ACCUMULATION
        Entry *entry = Super::find(key);
        if (entry)
        {
            event_to_region.erase((entry->data.offset_first << 16) | (entry->data.pc_first & (1 << 16 - 1)));
        }
#endif
        return Super::erase(key);
    }
#ifdef SHORT_ACCUMULATION
    uint64_t search_by_event(uint64_t pc, int offset)
    {
        uint64_t key = (offset << 16) | (pc & (1 << 16 - 1));
        if (event_to_region.count(key))
            return event_to_region[key];
        else
            return 0;
    }
#endif

    int get_pattern_len() { return this->pattern_len; }

    string log()
    {
        vector<string> headers({"Region", "PC_first", "Offset_first", "Pattern"});
        return Super::log(headers);
    }

private:
    /* @override */
    void write_data(Entry &entry, Table &table, int row)
    {
        uint64_t key = hash_index(entry.key, this->index_len);
        table.set_cell(row, 0, key);
        table.set_cell(row, 1, entry.data.pc_first);
        table.set_cell(row, 2, entry.data.offset_first);
        table.set_cell(row, 3, rsa_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t region_number)
    {
        uint64_t key = region_number & ((1ULL << (42 - __builtin_ctz(pattern_len))) - 1);
        return hash_index(key, this->index_len);
    }

    int pattern_len;
#ifdef SHORT_ACCUMULATION
    unordered_map<uint64_t, uint64_t> event_to_region;
#endif

    /*===============================================================*/
    /* Entry   = [tag, map, offset, PC, valid, LRU]                  */
    /* Storage = size * (37 - lg(sets) + 32 + 5 + 16 + 1 + lg(ways)) */
    /* 128 * (37 - lg(8) + 32 + 5 + 16 + 1 + lg(16)) = 1472 Bytes    */
    /*===============================================================*/
};

template <class T>
vector<T> rsa_rotate(const vector<T> &x, int n)
{
    vector<T> y;
    int len = x.size();
    n = n % len;
    for (int i = 0; i < len; i += 1)
        y.push_back(x[(i - n + len) % len]);
    return y;
}

class PHTData
{
public:
    vector<bool> pattern;
};

class PHT : public LRUSetAssociativeCache<PHTData>
{
    typedef LRUSetAssociativeCache<PHTData> Super;

public:
    PHT(int size, int pattern_len, int pc_width, int offset_width, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len), pc_width(pc_width), offset_width(offset_width)
    {
        // assert(this->pc_width >= 0);
        // assert(this->min_addr_width >= 0);
        // assert(this->max_addr_width >= 0);
        // assert(this->max_addr_width >= this->min_addr_width);
        // assert(this->pc_width + this->min_addr_width > 0);
        // assert(__builtin_popcount(pattern_len) == 1);
        if (this->debug_level >= 1)
            cerr << "PHT::PHT(size=" << size << ", pattern_len=" << pattern_len
                 << ", pc_width=" << pc_width << ", offset_width=" << offset_width
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")"
                 << dec << endl;
    }

    void insert(uint64_t pc, int offset, vector<bool> pattern)
    {
        if (this->debug_level >= 2)
            cerr << "PHT::insert(pc=0x" << hex << pc << ", offset=" << offset
                 << ", pattern=" << rsa_pattern_to_string(pattern) << ")" << dec << endl;
        // assert((int)pattern.size() == this->pattern_len);
        pattern = rsa_rotate(pattern, -offset);
        uint64_t key = this->build_key(pc, offset);
        Super::insert(key, {pattern});
        Super::set_mru(key);
    }

    vector<bool> find(uint64_t pc, int offset)
    {
        if (this->debug_level >= 2)
            cerr << "PHT::find(pc=0x" << hex << pc << ", offset=" << dec << offset << ")" << dec << endl;
        uint64_t key = this->build_key(pc, offset);
        Entry *entry = Super::find(key);
        if (!entry)
        {
            if (this->debug_level >= 2)
                cerr << "[PHT::find] Not found!" << dec << endl;
            return vector<bool>();
        }
        vector<bool> pattern = entry->data.pattern;
        pattern = rsa_rotate(pattern, +offset);
        Super::set_mru(key);
        return pattern;
    }

    Entry *erase(uint64_t pc, int offset)
    {
        uint64_t key = this->build_key(pc, offset);
        return Super::erase(key);
    }

    string log()
    {
        vector<string> headers({"PC", "Offset", "Pattern"});
        return Super::log(headers);
    }

    int get_pattern_len() { return this->pattern_len; }

private:
    /* @override */
    void write_data(Entry &entry, Table &table, int row)
    {
        uint64_t key = hash_index(entry.key, this->index_len);
        uint64_t pc = key >> this->offset_width;
        int offset = key & ((1 << this->offset_width) - 1);
        table.set_cell(row, 0, pc);
        table.set_cell(row, 1, offset);
        table.set_cell(row, 2, rsa_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t pc, int offset)
    {
        pc &= (1 << this->pc_width) - 1;
        uint64_t key = (pc << this->offset_width) | offset;
        return hash_index(key, this->index_len);
    }

    int pattern_len;
    int pc_width, offset_width;

    /*======================================================*/
    /* Entry   = [tag, map, valid, LRU]                     */
    /* Storage = size * (32 - lg(sets) + 32 + 1 + lg(ways)) */
    /* 8K * (32 - lg(512) + 32 + 1 + lg(16)) = 60K Bytes    */
    /*======================================================*/
};

class PBData
{
public:
    /* contains the prefetch fill level for each block of spatial region */
    vector<bool> pattern;
};

class PB : public LRUSetAssociativeCache<PBData>
{
    typedef LRUSetAssociativeCache<PBData> Super;

public:
    PB(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len)
    {
        if (this->debug_level >= 1)
            cerr << "PB::PB(size=" << size << ", pattern_len=" << pattern_len
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
    }

    void insert(uint64_t region_number, vector<bool> pattern)
    {
        if (this->debug_level >= 2)
            cerr << "PB::insert(region_number=0x" << hex << region_number
                 << ", pattern=" << rsa_pattern_to_string(pattern) << ")" << dec << endl;
        uint64_t key = this->build_key(region_number);

        Entry *entry = Super::find(key);
        if (!entry)
        {
            Super::insert(key, {pattern});
        }
        else
        {
            for (size_t i = 0; i < pattern.size(); i++)
            {
                if (pattern[i])
                    entry->data.pattern[i] = pattern[i];
            }
        }
        Super::set_mru(key);
    }

    int prefetch(CACHE *cache, uint64_t block_address)
    {
        if (this->debug_level >= 2)
        {
            cerr << "PB::prefetch(cache=" << cache->NAME << ", block_address=0x" << hex << block_address
                 << ")" << dec << endl;
            cerr << "[PB::prefetch] " << cache->PQ.occupancy << "/" << cache->PQ.SIZE
                 << " PQ entries occupied." << dec << endl;
            cerr << "[PB::prefetch] " << cache->MSHR.occupancy << "/" << cache->MSHR.SIZE
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
                cerr << "[PB::prefetch] No entry found." << dec << endl;
            return 0;
        }
        Super::set_mru(key);
        int pf_issued = 0;
        vector<bool> &pattern = entry->data.pattern;
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
                        cache->prefetch_line(0, base_addr, pf_address, FILL_L2, 0);
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
        table.set_cell(row, 1, rsa_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t region_number) { return hash_index(region_number, this->index_len); }

    int pattern_len;

    /*======================================================*/
    /* Entry   = [tag, map, valid, LRU]                     */
    /* Storage = size * (53 - lg(sets) + 64 + 1 + lg(ways)) */
    /* 128 * (53 - lg(8) + 64 + 1 + lg(16)) = 1904 Bytes    */
    /*======================================================*/
};

class RSA : public Prefetcher
{
public:
    RSA(string type, CACHE *cache);
    ~RSA();
    void invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr);
    void register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr);
    void dump_stats();
    void print_config();

    /**
     * Updates RSA's state based on the most recent LOAD access.
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
    vector<bool> find_in_pht(uint64_t pc, uint64_t address, int &next_ft_level);

    void insert_in_pht(const AT::Entry &entry, int at_level);

    void init_knobs();
    void init_stats();

    /*======================*/
    CACHE *parent = NULL;
    int32_t levels;
    vector<uint32_t> pattern_len;
    vector<FT> ft;
    vector<AT> at;
    vector<PHT> pht;
    PB pb;
    int default_insert_level;
    int debug_level = 0;

    /* stats */
    uint64_t pht_access_cnt = 0;
    uint64_t pht_pc_address_cnt = 0;
    uint64_t pht_pc_offset_cnt = 0;
    uint64_t pht_miss_cnt = 0;

    uint64_t prefetch_cnt = {0};
    uint64_t useful_cnt = {0};
    uint64_t useless_cnt = {0};

    unordered_map<int, uint64_t> pref_level_cnt;
    uint64_t region_pref_cnt = 0;
};

#endif /* RSA_H */
