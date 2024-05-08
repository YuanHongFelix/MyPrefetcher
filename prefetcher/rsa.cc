#include <iostream>
#include <vector>
#include "cache.h"
#include "champsim.h"
#include "rsa.h"

namespace knob
{
    extern uint32_t rsa_levels;
    extern vector<uint32_t> rsa_region_size;
    extern vector<uint32_t> rsa_pattern_len;
    extern uint32_t rsa_pc_width;
    extern vector<uint32_t> rsa_offset_width;
    extern vector<uint32_t> rsa_ft_size;
    extern vector<uint32_t> rsa_at_size;
    extern vector<uint32_t> rsa_pht_size;
    extern uint32_t rsa_pht_ways;
    extern uint32_t rsa_pb_size;
    extern uint32_t rsa_default_insert_level;
    extern float rsa_thresh;
    extern uint32_t rsa_debug_level;
}

void RSA::init_knobs()
{
}

void RSA::init_stats()
{
}

RSA::RSA(string type, CACHE *cache) : Prefetcher(type), parent(cache),
                                      levels(knob::rsa_levels), pattern_len(knob::rsa_pattern_len),
                                      default_insert_level(knob::rsa_default_insert_level),
                                      pb(knob::rsa_pb_size, pattern_len[levels - 1], knob::rsa_debug_level),
                                      debug_level(knob::rsa_debug_level)
{
    init_knobs();
    init_stats();
    for (int i = 0; i < levels; i++)
    {
        ft.emplace_back(FT(knob::rsa_ft_size[i], pattern_len[i], knob::rsa_debug_level));
        at.emplace_back(AT(knob::rsa_at_size[i], pattern_len[i], knob::rsa_debug_level));
        pht.emplace_back(PHT(knob::rsa_pht_size[i], pattern_len[i], knob::rsa_pc_width, knob::rsa_offset_width[i], knob::rsa_debug_level, knob::rsa_pht_ways));
    }
}

RSA::~RSA()
{
}

template <typename T>
std::ostream &operator<<(std::ostream &os, const std::vector<T> &vec)
{
    os << "[";
    for (size_t i = 0; i < vec.size(); ++i)
    {
        os << vec[i];
        if (i != vec.size() - 1)
        {
            os << ", ";
        }
    }
    os << "]";
    return os;
}

void RSA::print_config()
{
    cout << "rsa_levels" << knob::rsa_levels << endl
         << "rsa_region_size " << knob::rsa_region_size << endl
         << "rsa_pattern_len " << knob::rsa_pattern_len << endl
         << "rsa_pc_width " << knob::rsa_pc_width << endl
         << "rsa_offset_width " << knob::rsa_offset_width << endl
         << "rsa_ft_size " << knob::rsa_ft_size << endl
         << "rsa_at_size " << knob::rsa_at_size << endl
         << "rsa_pht_size " << knob::rsa_pht_size << endl
         << "rsa_pht_ways " << knob::rsa_pht_ways << endl
         << "rsa_pf_streamer_size " << knob::rsa_pb_size << endl
         << "rsa_thresh " << knob::rsa_thresh << endl
         << "rsa_default_insert_level " << knob::rsa_default_insert_level << endl
         << "rsa_debug_level " << knob::rsa_debug_level << endl
         << endl;
}

void RSA::access(uint64_t block_number, uint64_t pc)
{
    if (this->debug_level >= 2)
        cerr << "[RSA] access(block_number=0x" << hex << block_number << ", pc=0x" << pc << ")" << dec << endl;

    for (size_t i = 0; i < levels; i++)
    {
        uint64_t region_number = block_number / this->at[i].get_pattern_len();
        int region_offset = block_number % this->at[i].get_pattern_len();
        bool success = this->at[i].set_pattern(region_number, region_offset);
        if (success)
            return;
    }

    int ft_hit_level = -1;
    FT::Entry *entry = nullptr;
    for (size_t i = 0; i < levels; i++)
    {
        uint64_t region_number = block_number / this->ft[i].get_pattern_len();
        entry = this->ft[i].find(region_number);
        if (entry)
        {
            ft_hit_level = i;
            break;
        }
    }

    if (!entry)
    {
        /* trigger access */
#ifdef SHORT_ACCUMULATION
        AT::Entry *at_entry;
        int at_hit_level = -1;
        for (size_t i = 0; i < levels; i++)
        {
            int region_offset = block_number % this->at[i].get_pattern_len();
            uint64_t temp = at[i].search_by_event(pc, region_offset);
            at_entry = this->at[i].erase(temp);
            if (at_entry)
            {
                at_hit_level = i;
                break;
            }
        }
        if (at_hit_level > 0)
        {
            insert_in_pht(*at_entry, at_hit_level);
        }
#endif
        int pht_hit_level = -1;
        vector<bool> pattern = this->find_in_pht(pc, block_number, pht_hit_level);
        int ft_insert_level = pht_hit_level < 0 ? knob::rsa_default_insert_level : pht_hit_level;

        uint64_t region_number = block_number / this->ft[ft_insert_level].get_pattern_len();
        int region_offset = block_number % this->ft[ft_insert_level].get_pattern_len();
        this->ft[ft_insert_level].insert(region_number, pc, region_offset);

        // daixiugai
        if (!pattern.empty())
        {
            vector<bool> expand_pattern(pattern_len[levels - 1], 0);
            int start = (block_number % pattern_len[levels - 1]) / pattern.size() * pattern.size();
            for (size_t i = 0; i < pattern.size(); i++)
            {
                expand_pattern[start + i] = pattern[i];
            }

            this->pb.insert(block_number / this->pattern_len[levels - 1], expand_pattern);
        }
        return;
    }

    int region_offset = block_number % this->pattern_len[ft_hit_level];
    if (entry->data.offset != region_offset)
    {
        /* move from filter table to accumulation table */
        uint64_t region_number = hash_index(entry->key, this->ft[ft_hit_level].get_index_len());
        int insert_at_level = ft_hit_level;
        uint64_t region_insert = region_number;
        uint64_t pc_first, pc_second = entry->data.pc;
        int offset_first, offset_second = entry->data.offset;
        vector<bool> pattern_insert(this->at[ft_hit_level].get_pattern_len(), 0);
        AT::Entry *old_entry = nullptr;
        if (ft_hit_level != levels - 1)
        {
            if (region_number & 1)
            {
                old_entry = this->at[ft_hit_level].erase(region_number - 1);
                if (old_entry)
                {
                    insert_at_level++;
                    region_insert >>= 1;
                    pc_first = old_entry->data.pc_first;
                    offset_first = old_entry->data.offset_first;
                    offset_second += this->at[ft_hit_level].get_pattern_len();
                    pattern_insert.resize(this->at[insert_at_level].get_pattern_len());
                    for (size_t i = 0; i < old_entry->data.pattern.size(); i++)
                    {
                        pattern_insert[i] = old_entry->data.pattern[i];
                    }
                    pattern_insert[entry->data.offset + pattern_insert.size() / 2] = 1;
                    pattern_insert[region_offset + pattern_insert.size() / 2] = 1;
                }
            }
            else
            {
                old_entry = this->at[ft_hit_level].erase(region_number + 1);
                if (old_entry)
                {
                    insert_at_level++;
                    region_insert >>= 1;
                    pc_first = old_entry->data.pc_first;
                    offset_first = old_entry->data.offset_first + this->at[ft_hit_level].get_pattern_len();
                    pattern_insert.resize(this->at[insert_at_level].get_pattern_len());
                    for (size_t i = 0; i < old_entry->data.pattern.size(); i++)
                    {
                        pattern_insert[i + pattern_insert.size() / 2] = old_entry->data.pattern[i];
                    }
                    pattern_insert[entry->data.offset] = 1;
                    pattern_insert[region_offset] = 1;
                }
            }
        }
        AT::Entry victim;
        if (ft_hit_level == insert_at_level)
        {
            victim = this->at[insert_at_level].insert(region_insert, entry->data.pc, entry->data.offset);
            this->at[insert_at_level].set_pattern(region_insert, region_offset);
        }
        else
        {
            victim = this->at[insert_at_level].insert(region_insert, pc_first, offset_first, pc_second, offset_second, pattern_insert);
        }
        this->ft[ft_hit_level].erase(region_number);
        if (victim.valid)
        {
            /* move from accumulation table to PHT */
            this->insert_in_pht(victim, insert_at_level);
        }
    }
}

void RSA::eviction(uint64_t block_number)
{
    if (this->debug_level >= 2)
        cerr << "[RSA] eviction(block_number=" << block_number << ")" << dec << endl;
    /* end of generation: footprint must now be stored in PHT */

    for (size_t i = 0; i < this->at.size(); i++)
    {
        uint64_t region_number = block_number / this->at[i].get_pattern_len();
        this->ft[i].erase(region_number);
        AT::Entry *entry = this->at[i].erase(region_number);
        if (entry)
        {
            this->insert_in_pht(*entry, i);
            break;
        }
    }
}

int RSA::prefetch(uint64_t block_number)
{
    int pf_issued = this->pb.prefetch(parent, block_number);
    if (this->debug_level >= 2)
        cerr << "[RSA::prefetch] pf_issued=" << pf_issued << dec << endl;
    return pf_issued;
}

void RSA::set_debug_level(int debug_level)
{
    for (size_t i = 0; i < levels; i++)
    {

        this->ft[i].set_debug_level(debug_level);
        this->at[i].set_debug_level(debug_level);
        this->pht[i].set_debug_level(debug_level);
    }
    this->pb.set_debug_level(debug_level);
    this->debug_level = debug_level;
}

void RSA::log()
{
    for (size_t i = 0; i < levels; i++)
    {

        cerr << "Filter Table " << i << ":" << dec << endl;
        cerr << this->ft[i].log();
    }
    for (size_t i = 0; i < levels; i++)
    {

        cerr << "Accumulation Table " << i << ":" << dec << endl;
        cerr << this->at[i].log();
    }
    for (size_t i = 0; i < levels; i++)
    {

        cerr << "Pattern History Table " << i << ":" << dec << endl;
        cerr << this->pht[i].log();
    }
    cerr << "PB:" << dec << endl;
    cerr << this->pb.log();
}

vector<bool> RSA::find_in_pht(uint64_t pc, uint64_t address, int &hit_level)
{
    if (this->debug_level >= 2)
    {
        cerr << "[RSA] find_in_pht(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
    }
    vector<bool> pattern;
    for (size_t i = 0; i < levels; i++)
    {
        int offset = address % this->pht[i].get_pattern_len();
        pattern = this->pht[i].find(pc, offset);
        if (!pattern.empty())
        {
            hit_level = i;
            return pattern;
        }
    }
    hit_level = -1;
    return vector<bool>();
}

template <typename T>
std::vector<T> operator+(const std::vector<T> &v1, const std::vector<T> &v2)
{
    std::vector<T> result;
    result.reserve(v1.size() + v2.size()); // 预分配足够的空间

    result.insert(result.end(), v1.begin(), v1.end()); // 将v1的元素添加到result中
    result.insert(result.end(), v2.begin(), v2.end()); // 将v2的元素添加到result中

    return result;
}

bool check_half_zero(const vector<bool> &v, int l, int r)
{
    for (size_t i = l; i < r; i++)
    {
        if (v[i])
            return false;
    }
    return true;
}

vector<bool> vector_or(const vector<bool> &v1, const vector<bool> &v2, int l, int r)
{
    vector<bool> result(r - l);
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = v1[l + i] || v2[l + i];
    }
    return result;
}

bool compare_accuracy(const vector<bool> &x, const vector<bool> &y, int l, int r)
{
    int count = 0;
    for (size_t i = l; i < r; i++)
    {
        if (x[i] ^ y[i])
            count++;
    }
    if (count < (r - l) * knob::rsa_thresh)
        return false;
    return true;
}

vector<bool> sub_vector(const vector<bool> &v, int l, int r)
{
    vector<bool> result(r - l);
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = v[l + i];
    }
    return result;
}

void RSA::insert_in_pht(const AT::Entry &entry, int at_level)
{
    if (entry.data.is_level_up)
    {
        uint64_t pc = entry.data.pc_first;
        int offset = entry.data.offset_first;
        vector<bool> new_pattern = entry.data.pattern;
        vector<bool> old_pattern_first = this->pht[at_level - 1].find(entry.data.pc_first, entry.data.offset_first);
        vector<bool> old_pattern_second = this->pht[at_level - 1].find(entry.data.pc_second, entry.data.offset_second);
        if (entry.data.offset_first < entry.data.offset_second)
        {
            vector<bool> new_pattern_first = sub_vector(new_pattern, 0, new_pattern.size() / 2);
            vector<bool> new_pattern_second = sub_vector(new_pattern, new_pattern.size() / 2, new_pattern.size());
            if (!old_pattern_first.empty() && compare_accuracy(new_pattern_first, old_pattern_first, 0, new_pattern_first.size()))
            {
                new_pattern_first = vector_or(new_pattern_first, old_pattern_first, 0, new_pattern_first.size());
            }
            if (!old_pattern_second.empty() && compare_accuracy(new_pattern_second, old_pattern_second, 0, new_pattern_second.size()))
            {
                new_pattern_second = vector_or(new_pattern_second, old_pattern_second, 0, new_pattern_second.size());
            }
            new_pattern = new_pattern_first + new_pattern_second;
            this->pht[at_level].insert(pc, offset, new_pattern);
        }
        else
        {
            vector<bool> new_pattern_first = sub_vector(new_pattern, new_pattern.size() / 2, new_pattern.size());
            vector<bool> new_pattern_second = sub_vector(new_pattern, 0, new_pattern.size() / 2);
            if (!old_pattern_first.empty() && compare_accuracy(new_pattern_first, old_pattern_first, 0, new_pattern_first.size()))
            {
                new_pattern_first = vector_or(new_pattern_first, old_pattern_first, 0, new_pattern_first.size());
            }
            if (!old_pattern_second.empty() && compare_accuracy(new_pattern_second, old_pattern_second, 0, new_pattern_second.size()))
            {
                new_pattern_second = vector_or(new_pattern_second, old_pattern_second, 0, new_pattern_second.size());
            }
            new_pattern = new_pattern_second + new_pattern_first;
            this->pht[at_level].insert(pc, offset, new_pattern);
        }
        this->pht[at_level - 1].erase(entry.data.pc_first, entry.data.offset_first);
        this->pht[at_level - 1].erase(entry.data.pc_second, entry.data.offset_second);
    }
    else
    {
        uint64_t pc = entry.data.pc_first;
        int offset = entry.data.offset_first;
        vector<bool> new_pattern = entry.data.pattern;
        vector<bool> old_pattern = this->pht[at_level].find(pc, offset);
        if (old_pattern.empty())
        {
            this->pht[at_level].insert(pc, offset, new_pattern);
        }
        else
        {
            if (at_level == 0)
            {
                if (compare_accuracy(new_pattern, old_pattern, 0, new_pattern.size()))
                    this->pht[at_level].insert(pc, offset, vector_or(new_pattern, old_pattern, 0, new_pattern.size()));
                else
                    this->pht[at_level].insert(pc, offset, new_pattern);
            }
            else
            {
                if (offset < new_pattern.size() / 2)
                {
#ifdef ACCURACY_LEVELDOWN
                    if (check_half_zero(new_pattern, new_pattern.size() / 2, new_pattern.size()) || !compare_accuracy(new_pattern, old_pattern, new_pattern.size() / 2, new_pattern.size()))
#else
                    if (check_half_zero(new_pattern, new_pattern.size() / 2, new_pattern.size()))
#endif
                    {
                        if (compare_accuracy(new_pattern, old_pattern, 0, new_pattern.size() / 2))
                            this->pht[at_level - 1].insert(pc, offset, vector_or(new_pattern, old_pattern, 0, new_pattern.size() / 2));
                        else
                            this->pht[at_level - 1].insert(pc, offset, sub_vector(new_pattern, 0, new_pattern.size() / 2));
                        this->pht[at_level].erase(pc, offset);
                    }
                    else
                    {
                        if (compare_accuracy(new_pattern, old_pattern, 0, new_pattern.size()))
                            this->pht[at_level].insert(pc, offset, vector_or(new_pattern, old_pattern, 0, new_pattern.size()));
                        else
                            this->pht[at_level].insert(pc, offset, new_pattern);
                    }
                }
                else
                {
#ifdef ACCURACY_LEVELDOWN
                    if (check_half_zero(new_pattern, 0, new_pattern.size() / 2) || !compare_accuracy(new_pattern, old_pattern, 0, new_pattern.size() / 2))
#else
                    if (check_half_zero(new_pattern, 0, new_pattern.size() / 2))
#endif
                    {
                        if (compare_accuracy(new_pattern, old_pattern, new_pattern.size() / 2, new_pattern.size()))
                            this->pht[at_level - 1].insert(pc, offset % (new_pattern.size() / 2), vector_or(new_pattern, old_pattern, new_pattern.size() / 2, new_pattern.size()));
                        else
                            this->pht[at_level - 1].insert(pc, offset % (new_pattern.size() / 2), sub_vector(new_pattern, new_pattern.size() / 2, new_pattern.size()));
                        this->pht[at_level].erase(pc, offset);
                    }
                    else
                    {
                        if (compare_accuracy(new_pattern, old_pattern, 0, new_pattern.size()))
                            this->pht[at_level].insert(pc, offset, vector_or(new_pattern, old_pattern, 0, new_pattern.size()));
                        else
                            this->pht[at_level].insert(pc, offset, new_pattern);
                    }
                }
            }
        }
    }
}

/* Base-class virtual function */
void RSA::invoke_prefetcher(uint64_t pc, uint64_t addr, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr)
{
    if (debug_level >= 2)
    {
        cerr << "CACHE::l2C_prefetcher_operate(addr=0x" << hex << addr << ", PC=0x" << pc << ", cache_hit=" << dec
             << (int)cache_hit << ", type=" << (int)type << ")" << dec << endl;
    }

    if (type != LOAD)
        return;

    uint64_t block_number = addr >> LOG2_BLOCK_SIZE;

    /* update RSA with most recent LOAD access */
    access(block_number, pc);

    /* issue prefetches */
    prefetch(block_number);

    if (debug_level >= 3)
    {
        log();
        cerr << "=======================================" << dec << endl;
    }
}

void RSA::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr)
{
    uint64_t evicted_block_number = evicted_addr >> LOG2_BLOCK_SIZE;

    if (parent->block[set][way].valid == 0)
        return; /* no eviction */

    /* inform all modules of the eviction */
    /* RBERA: original code was to send eviction signal to RSA in every core
     * modified it to make the signal local */
    eviction(evicted_block_number);
}

void RSA::dump_stats()
{
    // print_stats();
}
