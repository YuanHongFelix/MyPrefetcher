#ifndef RB_H
#define RB_H

// #define SHORT_ACCUMULATION_RB
#define ACCURACY_LEVELDOWN_RB

#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include "prefetcher.h"
#include "cache.h"
#include "bakshalipour_framework.h"

using namespace std;

template <class T>
string rb_pattern_to_string(const vector<T> &pattern)
{
    ostringstream oss;
    for (unsigned i = 0; i < pattern.size(); i += 1)
        oss << int(pattern[i]);
    return oss.str();
}

class FTDataRB
{
public:
    uint64_t pc;
    int offset;
    vector<bool> pattern_prefetch;
};

class FTRB : public LRUSetAssociativeCache<FTDataRB>
{
    typedef LRUSetAssociativeCache<FTDataRB> Super;

public:
    FTRB(int size, int pattern_len, int debug_level = 0, int num_ways = 16) : Super(size, num_ways, debug_level), pattern_len(pattern_len)
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

    void insert(uint64_t region_number, uint64_t pc, int offset, vector<bool> pattern_prefetch)
    {
        if (this->debug_level >= 2)
            cerr << "FT::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
                 << ", offset=" << dec << offset << ")"
                 << ", pattern_prefetch=" << rb_pattern_to_string(pattern_prefetch)
                 << dec << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        Super::insert(key, {pc, offset, pattern_prefetch});
        Super::set_mru(key);
    }

    Entry *erase(uint64_t region_number)
    {
        uint64_t key = this->build_key(region_number);
        return Super::erase(key);
    }

    string log()
    {
        vector<string> headers({"Region", "PC", "Offset", "Pattern_prefetch"});
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
        table.set_cell(row, 3, rb_pattern_to_string(entry.data.pattern_prefetch));
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

class ATDataRB
{
public:
    uint64_t pc;
    int offset;
    vector<bool> pattern;
    vector<bool> pattern_prefetch;
};

class ATRB : public LRUSetAssociativeCache<ATDataRB>
{
    typedef LRUSetAssociativeCache<ATDataRB> Super;

public:
    ATRB(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
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
    Entry insert(uint64_t region_number, uint64_t pc, int offset, vector<bool> pattern_prefetch)
    {
        if (this->debug_level >= 2)
            cerr << "AT::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
                 << ", offset=" << dec << offset
                 << ", pattern_prefetch=" << rb_pattern_to_string(pattern_prefetch)
                 << dec << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        vector<bool> pattern(this->pattern_len, false);
        pattern[offset] = true;
        Entry old_entry = Super::insert(key, {pc, offset, pattern, pattern_prefetch});
#ifdef SHORT_ACCUMULATION
        event_to_region[(offset << 16) | (pc & (1 << 16 - 1))] = region_number;
#endif
        Super::set_mru(key);
        return old_entry;
    }

    Entry insert(uint64_t region_number, uint64_t pc, int offset, vector<bool> pattern, vector<bool> pattern_prefetch)
    {
        if (this->debug_level >= 2)
            cerr << "AT::insert(region_number=0x" << hex << region_number
                 << ", pc=0x" << pc << ", offset=" << dec << offset << dec
                 << ", pattern=" << rb_pattern_to_string(pattern)
                 << ", pattern_prefetch=" << rb_pattern_to_string(pattern_prefetch)
                 << endl;
        uint64_t key = this->build_key(region_number);
        // assert(!Super::find(key));
        Entry old_entry = Super::insert(key, {pc, offset, pattern, pattern_prefetch});
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
        vector<string> headers({"Region", "PC", "Offset", "Pattern", "Pattern_prefetch"});
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
        table.set_cell(row, 3, rb_pattern_to_string(entry.data.pattern));
        table.set_cell(row, 4, rb_pattern_to_string(entry.data.pattern_prefetch));
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

enum EventPB
{
    PC_ADDRESS_PB = 0,
    PC_OFFSET_PB = 1,
    MISS_PB = 2
};

template <class T>
vector<T> rb_rotate(const vector<T> &x, int n)
{
    vector<T> y;
    int len = x.size();
    n = n % len;
    for (int i = 0; i < len; i += 1)
        y.push_back(x[(i - n + len) % len]);
    return y;
}

class PHTDataRB
{
public:
    vector<bool> pattern;
};

class PHTRB : public LRUSetAssociativeCache<PHTDataRB>
{
    typedef LRUSetAssociativeCache<PHTDataRB> Super;

public:
    PHTRB(int size, int pattern_len, int pc_width, int min_addr_width, int max_addr_width, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len), pc_width(pc_width), min_addr_width(min_addr_width), max_addr_width(max_addr_width)
    {
        // assert(this->pc_width >= 0);
        // assert(this->min_addr_width >= 0);
        // assert(this->max_addr_width >= 0);
        // assert(this->max_addr_width >= this->min_addr_width);
        // assert(this->pc_width + this->min_addr_width > 0);
        // assert(__builtin_popcount(pattern_len) == 1);
        if (this->debug_level >= 1)
            cerr << "PHT::PHT(size=" << size << ", pattern_len=" << pattern_len
                 << ", pc_width=" << pc_width
                 << ", min_addr_width=" << min_addr_width << ", max_addr_width=" << max_addr_width
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")"
                 << dec << endl;
    }

    void insert(uint64_t pc, uint64_t address, vector<bool> pattern)
    {
        if (this->debug_level >= 2)
            cerr << "PHT::insert(pc=0x" << hex << pc << ", address=0x" << address
                 << ", pattern=" << rb_pattern_to_string(pattern) << ")" << dec << endl;
        // assert((int)pattern.size() == this->pattern_len);
        int offset = address % this->pattern_len;
        pattern = rb_rotate(pattern, -offset);
        uint64_t key = this->build_key(pc, address);
        Super::insert(key, {pattern});
        Super::set_mru(key);
    }

    Entry *erase(uint64_t pc, uint64_t address)
    {
        uint64_t key = this->build_key(pc, address);
        return Super::erase(key);
    }

    vector<vector<bool>> find(uint64_t pc, uint64_t address)
    {
        if (this->debug_level >= 2)
            cerr << "PHT::find(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
        uint64_t key = this->build_key(pc, address);
        uint64_t index = key % this->num_sets;
        uint64_t tag = key / this->num_sets;
        auto &set = this->entries[index];
        uint64_t min_tag_mask = (1 << (this->pc_width + this->min_addr_width - this->index_len)) - 1;
        uint64_t max_tag_mask = (1 << (this->pc_width + this->max_addr_width - this->index_len)) - 1;
        vector<vector<bool>> matches;
        this->last_event = MISS_PB;
        for (int i = 0; i < this->num_ways; i += 1)
        {
            if (!set[i].valid)
                continue;
            bool min_match = ((set[i].tag & min_tag_mask) == (tag & min_tag_mask));
            bool max_match = ((set[i].tag & max_tag_mask) == (tag & max_tag_mask));
            vector<bool> &cur_pattern = set[i].data.pattern;
            if (max_match)
            {
                this->last_event = PC_ADDRESS_PB;
                Super::set_mru(set[i].key);
                matches.clear();
                matches.push_back(cur_pattern);
                break;
            }
            if (min_match)
            {
                this->last_event = PC_OFFSET_PB;
                matches.push_back(cur_pattern);
            }
        }
        int offset = address % this->pattern_len;
        for (int i = 0; i < (int)matches.size(); i += 1)
            matches[i] = rb_rotate(matches[i], +offset);
        return matches;
    }

    EventPB get_last_event() { return this->last_event; }

    string log()
    {
        vector<string> headers({"PC", "Offset", "Address", "Pattern"});
        return Super::log(headers);
    }

    int get_pattern_len() { return this->pattern_len; }

private:
    /* @override */
    void write_data(Entry &entry, Table &table, int row)
    {
        uint64_t base_key = entry.key >> (this->pc_width + this->min_addr_width);
        uint64_t index_key = entry.key & ((1 << (this->pc_width + this->min_addr_width)) - 1);
        index_key = hash_index(index_key, this->index_len); /* unhash */
        uint64_t key = (base_key << (this->pc_width + this->min_addr_width)) | index_key;

        /* extract PC, offset, and address */
        uint64_t offset = key & ((1 << this->min_addr_width) - 1);
        key >>= this->min_addr_width;
        uint64_t pc = key & ((1 << this->pc_width) - 1);
        key >>= this->pc_width;
        uint64_t address = (key << this->min_addr_width) + offset;

        table.set_cell(row, 0, pc);
        table.set_cell(row, 1, offset);
        table.set_cell(row, 2, address);
        table.set_cell(row, 3, rb_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t pc, uint64_t address)
    {
        pc &= (1 << this->pc_width) - 1;            /* use `pc_width` bits from pc */
        address &= (1 << this->max_addr_width) - 1; /* use `addr_width` bits from address */
        uint64_t offset = address & ((1 << this->min_addr_width) - 1);
        uint64_t base = (address >> this->min_addr_width);
        /* key = base + hash_index( pc + offset )
         * The index must be computed from only PC+Offset to ensure that all entries with the same
         * PC+Offset end up in the same set */
        uint64_t index_key = hash_index((pc << this->min_addr_width) | offset, this->index_len);
        uint64_t key = (base << (this->pc_width + this->min_addr_width)) | index_key;
        return key;
    }

    int pattern_len;
    int min_addr_width, max_addr_width, pc_width;
    EventPB last_event;

    /*======================================================*/
    /* Entry   = [tag, map, valid, LRU]                     */
    /* Storage = size * (32 - lg(sets) + 32 + 1 + lg(ways)) */
    /* 8K * (32 - lg(512) + 32 + 1 + lg(16)) = 60K Bytes    */
    /*======================================================*/
};

class PBDataRB
{
public:
    /* contains the prefetch fill level for each block of spatial region */
    vector<int> pattern;
};

class PBRB : public LRUSetAssociativeCache<PBDataRB>
{
    typedef LRUSetAssociativeCache<PBDataRB> Super;

public:
    PBRB(int size, int pattern_len, int pf_degree, int debug_level = 0, int num_ways = 16)
        : Super(size, num_ways, debug_level), pattern_len(pattern_len), pf_degree(pf_degree)
    {
        if (this->debug_level >= 1)
            cerr << "PB::PB(size=" << size << ", pattern_len=" << pattern_len
                 << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
    }

    void insert(uint64_t region_number, vector<int> pattern)
    {
        if (this->debug_level >= 2)
            cerr << "PB::insert(region_number=0x" << hex << region_number
                 << ", pattern=" << rb_pattern_to_string(pattern) << ")" << dec << endl;
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
        vector<int> &pattern = entry->data.pattern;
        if (this->debug_level >= 2)
            cerr << "[PB::prefetch] Found! pattern: " << rb_pattern_to_string(pattern) << dec << endl;
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
                    if (((pf_issued < pf_degree) || pf_degree <= 0) && (cache->PQ.occupancy + cache->MSHR.occupancy < cache->MSHR.SIZE - 1 && cache->PQ.occupancy < cache->PQ.SIZE))
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
        table.set_cell(row, 1, rb_pattern_to_string(entry.data.pattern));
    }

    uint64_t build_key(uint64_t region_number) { return hash_index(region_number, this->index_len); }

    int pattern_len;
    int pf_degree;

    /*======================================================*/
    /* Entry   = [tag, map, valid, LRU]                     */
    /* Storage = size * (53 - lg(sets) + 64 + 1 + lg(ways)) */
    /* 128 * (53 - lg(8) + 64 + 1 + lg(16)) = 1904 Bytes    */
    /*======================================================*/
};

class RB : public Prefetcher
{
public:
    RB(string type, CACHE *cache);
    ~RB();
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
    vector<int> find_in_pht(uint64_t pc, uint64_t address, int &next_ft_level);

    void insert_in_pht(const ATRB::Entry &entry, int at_level);

    vector<int> vote(const vector<vector<bool>> &x);

    void init_knobs();
    void init_stats();

    /*======================*/
    CACHE *parent = NULL;
    int32_t levels;
    vector<uint32_t> pattern_len;
    vector<FTRB> ft;
    vector<ATRB> at;
    vector<PHTRB> pht;
    PBRB pb;
    float thresh;
    int default_insert_level;
    int debug_level = 0;

    // stat
    int count_eu_check = 0;
    int count_region_expand = 0;
    int count_su_check = 0;
    int count_region_shrink = 0;

};

#endif /* RB_H */
