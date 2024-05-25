#include <iostream>
#include <vector>
#include "cache.h"
#include "champsim.h"
#include "rb_l1.h"

namespace knob
{
    extern uint32_t rb_l1_levels;
    extern vector<uint32_t> rb_l1_region_size;
    extern vector<uint32_t> rb_l1_pattern_len;
    extern uint32_t rb_l1_pc_width;
    extern vector<uint32_t> rb_l1_min_addr_width;
    extern uint32_t rb_l1_max_addr_width;
    extern vector<uint32_t> rb_l1_ft_size;
    extern vector<uint32_t> rb_l1_at_size;
    extern vector<uint32_t> rb_l1_pht_size;
    extern uint32_t rb_l1_pht_ways;
    extern uint32_t rb_l1_pb_size;
    extern uint32_t rb_l1_default_insert_level;
    extern float rb_l1_l2c_thresh;
    extern float rb_l1_llc_thresh;
    extern float rb_l1_accuracy_thresh;
    extern float rb_l1_or_thresh;
    extern int32_t rb_l1_pf_degree;
    extern uint32_t rb_l1_debug_level;
}

void RB_L1::init_knobs()
{
}

void RB_L1::init_stats()
{
}

RB_L1::RB_L1(string type, CACHE *cache) : Prefetcher(type), parent(cache),
                                    levels(knob::rb_l1_levels), pattern_len(knob::rb_l1_pattern_len),
                                    default_insert_level(knob::rb_l1_default_insert_level),
                                    pb(knob::rb_l1_pb_size, pattern_len[levels - 1], knob::rb_l1_pf_degree, knob::rb_l1_debug_level),
                                    debug_level(knob::rb_l1_debug_level)
{
    init_knobs();
    init_stats();
    for (int i = 0; i < levels; i++)
    {
        ft.emplace_back(FTRB_L1(knob::rb_l1_ft_size[i], pattern_len[i], knob::rb_l1_debug_level));
        at.emplace_back(ATRB_L1(knob::rb_l1_at_size[i], pattern_len[i], knob::rb_l1_debug_level));
        pht.emplace_back(PHTRB_L1(knob::rb_l1_pht_size[i], pattern_len[i], knob::rb_l1_pc_width, knob::rb_l1_min_addr_width[i], knob::rb_l1_max_addr_width, knob::rb_l1_debug_level, knob::rb_l1_pht_ways));
    }
}

RB_L1::~RB_L1()
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

template <typename T>
std::vector<T> operator+(const std::vector<T> &v1, const std::vector<T> &v2)
{
    std::vector<T> result;
    result.reserve(v1.size() + v2.size()); // 预分配足够的空间

    result.insert(result.end(), v1.begin(), v1.end()); // 将v1的元素添加到result中
    result.insert(result.end(), v2.begin(), v2.end()); // 将v2的元素添加到result中

    return result;
}

void RB_L1::print_config()
{
    cout << "rb_l1_levels" << knob::rb_l1_levels << endl
         << "rb_l1_region_size " << knob::rb_l1_region_size << endl
         << "rb_l1_pattern_len " << knob::rb_l1_pattern_len << endl
         << "rb_l1_pc_width " << knob::rb_l1_pc_width << endl
         << "rb_l1_min_addr_width " << knob::rb_l1_min_addr_width << endl
         << "rb_l1_max_addr_width " << knob::rb_l1_max_addr_width << endl
         << "rb_l1_ft_size " << knob::rb_l1_ft_size << endl
         << "rb_l1_at_size " << knob::rb_l1_at_size << endl
         << "rb_l1_pht_size " << knob::rb_l1_pht_size << endl
         << "rb_l1_pht_ways " << knob::rb_l1_pht_ways << endl
         << "rb_l1_pf_streamer_size " << knob::rb_l1_pb_size << endl
         << "rb_l1_l2c_thresh " << knob::rb_l1_l2c_thresh << endl
         << "rb_l1_llc_thresh " << knob::rb_l1_llc_thresh << endl
         << "rb_l1_accuracy_thresh " << knob::rb_l1_accuracy_thresh << endl
         << "rb_l1_or_thresh " << knob::rb_l1_or_thresh << endl
         << "rb_l1_pf_degree " << knob::rb_l1_pf_degree << endl
         << "rb_l1_default_insert_level " << knob::rb_l1_default_insert_level << endl
         << "rb_l1_debug_level " << knob::rb_l1_debug_level << endl
         << endl;
}

void RB_L1::access(uint64_t block_number, uint64_t pc)
{
    if (this->debug_level >= 2)
        cerr << "[RB_L1] access(block_number=0x" << hex << block_number << ", pc=0x" << pc << ")" << dec << endl;

    for (size_t i = 0; i < levels; i++)
    {
        uint64_t region_number = block_number / this->at[i].get_pattern_len();
        int region_offset = block_number % this->at[i].get_pattern_len();
        bool success = this->at[i].set_pattern(region_number, region_offset);
        if (success)
            return;
    }

    int ft_hit_level = -1;
    FTRB_L1::Entry *entry = nullptr;
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
#ifdef SHORT_ACCUMULATION_RB_L1
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
        vector<int> pattern = this->find_in_pht(pc, block_number, pht_hit_level);
        int ft_insert_level = pht_hit_level < 0 ? knob::rb_l1_default_insert_level : pht_hit_level;
        vector<bool> pattern_prefetch(this->pattern_len[ft_insert_level], false);
        if (!pattern.empty())
        {
            for (size_t i = 0; i < pattern_prefetch.size(); i++)
            {
                if (pattern[i])
                    pattern_prefetch[i] = true;
            }
        }

        uint64_t region_number = block_number / this->ft[ft_insert_level].get_pattern_len();
        int region_offset = block_number % this->ft[ft_insert_level].get_pattern_len();
        this->ft[ft_insert_level].insert(region_number, pc, region_offset, pattern_prefetch);

        // daixiugai
        if (!pattern.empty())
        {
            vector<int> expand_pattern(pattern_len[levels - 1], 0);
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
        uint64_t pc_trigger;
        int offset_trigger;
        vector<bool> pattern_insert(this->at[ft_hit_level].get_pattern_len(), 0);
        vector<bool> pattern_prefetch = entry->data.pattern_prefetch;
        ATRB_L1::Entry *old_entry = nullptr;
        if (ft_hit_level != levels - 1)
        {
            if (region_number & 1)
            {
                old_entry = this->at[ft_hit_level].erase(region_number - 1);
                if (old_entry)
                {
                    insert_at_level++;
                    region_insert >>= 1;
                    pc_trigger = old_entry->data.pc;
                    offset_trigger = old_entry->data.offset;
                    pattern_insert.resize(this->at[insert_at_level].get_pattern_len());
                    for (size_t i = 0; i < old_entry->data.pattern.size(); i++)
                    {
                        pattern_insert[i] = old_entry->data.pattern[i];
                    }
                    pattern_insert[entry->data.offset + pattern_insert.size() / 2] = 1;
                    pattern_insert[region_offset + pattern_insert.size() / 2] = 1;
                    pattern_prefetch = old_entry->data.pattern_prefetch + entry->data.pattern_prefetch;
                    if (debug_level >= 2)
                    {
                        cerr << "level up![old+new] new region=" << hex << region_insert << ",new pc=" << hex << pc_trigger << ", new offset=" << dec << offset_trigger
                             << ", new pattern=" << rb_l1_pattern_to_string(pattern_insert);
                    }
                    // remove the two pattern in pht, merge them and insert to the higher level
                    uint64_t new_address = hash_index(old_entry->key, this->at[ft_hit_level].get_index_len()) * this->pattern_len[ft_hit_level] + old_entry->data.offset;
                    vector<bool> left_pattern, right_pattern;
                    PHTRB_L1::Entry *left_entry = this->pht[ft_hit_level].erase(old_entry->data.pc, new_address);
                    PHTRB_L1::Entry *right_entry = this->pht[ft_hit_level].erase(pc, block_number);
                    if (left_entry)
                        left_pattern = left_entry->data.pattern;
                    else
                        left_pattern = vector<bool>(pattern_len[ft_hit_level], 0);
                    if (right_entry)
                        right_pattern = right_entry->data.pattern;
                    else
                        right_pattern = vector<bool>(pattern_len[ft_hit_level], 0);
                    if (left_entry || right_entry)
                    {
                        this->pht[insert_at_level].insert(old_entry->data.pc, new_address, left_pattern + right_pattern);
                    }
                }
            }
            else
            {
                old_entry = this->at[ft_hit_level].erase(region_number + 1);
                if (old_entry)
                {
                    insert_at_level++;
                    region_insert >>= 1;
                    pc_trigger = old_entry->data.pc;
                    offset_trigger = old_entry->data.offset + this->at[ft_hit_level].get_pattern_len();
                    pattern_insert.resize(this->at[insert_at_level].get_pattern_len());
                    for (size_t i = 0; i < old_entry->data.pattern.size(); i++)
                    {
                        pattern_insert[i + pattern_insert.size() / 2] = old_entry->data.pattern[i];
                    }
                    pattern_insert[entry->data.offset] = 1;
                    pattern_insert[region_offset] = 1;
                    pattern_prefetch = entry->data.pattern_prefetch + old_entry->data.pattern_prefetch;
                    if (debug_level >= 2)
                    {
                        cerr << "level up![new+old] new region=" << hex << region_insert << ",new pc=" << hex << pc_trigger << ", new offset=" << dec << offset_trigger
                             << ", new pattern=" << rb_l1_pattern_to_string(pattern_insert);
                    }
                    // remove the two pattern in pht, merge them and insert to the higher level
                    uint64_t new_address = hash_index(old_entry->key, this->at[ft_hit_level].get_index_len()) * this->pattern_len[ft_hit_level] + old_entry->data.offset;
                    vector<bool> left_pattern, right_pattern;
                    PHTRB_L1::Entry *left_entry = this->pht[ft_hit_level].erase(pc, block_number);
                    PHTRB_L1::Entry *right_entry = this->pht[ft_hit_level].erase(old_entry->data.pc, new_address);
                    if (left_entry)
                        left_pattern = left_entry->data.pattern;
                    else
                        left_pattern = vector<bool>(pattern_len[ft_hit_level], 0);
                    if (right_entry)
                        right_pattern = right_entry->data.pattern;
                    else
                        right_pattern = vector<bool>(pattern_len[ft_hit_level], 0);
                    if (left_entry || right_entry)
                    {
                        this->pht[insert_at_level].insert(old_entry->data.pc, new_address, left_pattern + right_pattern);
                    }
                }
            }
        }
        ATRB_L1::Entry victim;
        if (ft_hit_level == insert_at_level)
        {
            victim = this->at[insert_at_level].insert(region_insert, entry->data.pc, entry->data.offset, entry->data.pattern_prefetch);
            this->at[insert_at_level].set_pattern(region_insert, region_offset);
        }
        else
        {
            victim = this->at[insert_at_level].insert(region_insert, pc_trigger, offset_trigger, pattern_insert, pattern_prefetch);
        }
        this->ft[ft_hit_level].erase(region_number);
        if (victim.valid)
        {
            /* move from accumulation table to PHT */
            this->insert_in_pht(victim, insert_at_level);
        }
    }
}

void RB_L1::eviction(uint64_t block_number)
{
    if (this->debug_level >= 2)
        cerr << "[RB_L1] eviction(block_number=" << block_number << ")" << dec << endl;
    /* end of generation: footprint must now be stored in PHT */

    for (size_t i = 0; i < this->at.size(); i++)
    {
        uint64_t region_number = block_number / this->at[i].get_pattern_len();
        this->ft[i].erase(region_number);
        ATRB_L1::Entry *entry = this->at[i].erase(region_number);
        if (entry)
        {
            this->insert_in_pht(*entry, i);
            break;
        }
    }
}

int RB_L1::prefetch(uint64_t block_number)
{
    int pf_issued = this->pb.prefetch(parent, block_number);
    if (this->debug_level >= 2)
        cerr << "[RB_L1::prefetch] pf_issued=" << pf_issued << dec << endl;
    return pf_issued;
}

void RB_L1::set_debug_level(int debug_level)
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

void RB_L1::log()
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

vector<int> RB_L1::find_in_pht(uint64_t pc, uint64_t address, int &hit_level)
{
    if (this->debug_level >= 2)
    {
        cerr << "[RB_L1] find_in_pht(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
    }
    vector<vector<int>> pattern(levels, vector<int>());
    for (size_t i = 0; i < levels; i++)
    {
        vector<vector<bool>> matches = this->pht[i].find(pc, address);
        EventPB_L1 pht_last_event = this->pht[i].get_last_event();
        if (pht_last_event == PC_ADDRESS_PB_L1)
        {
            vector<int> res(this->pattern_len[i], 0);
            for (int j = 0; j < this->pattern_len[i]; j++)
                if (matches[0][j])
                    res[j] = FILL_L2;
            hit_level = i;
            if (debug_level >= 2)
            {
                cerr << "[RB_L1] find_in_pht: PC_ADDRESS" << endl;
            }
            return res;
        }
        else if (pht_last_event == PC_OFFSET_PB_L1)
        {
            pattern[i] = this->vote(matches);
        }
    }
    if (!pattern[this->default_insert_level].empty())
    {
        hit_level = this->default_insert_level;
        if (debug_level >= 2)
        {
            cerr << "[RB_L1] find_in_pht: return default_insert_level" << endl;
        }
        return pattern[this->default_insert_level];
    }
    for (int i = levels - 1; i >= 0; i -= 1)
    {
        if (!pattern[i].empty())
        {
            hit_level = i;
            if (debug_level >= 2)
            {
                cerr << "[RB_L1] find_in_pht: return level" << i << endl;
            }
            return pattern[i];
        }
    }
    if (debug_level >= 2)
    {
        cerr << "[RB_L1] find_in_pht: ALL MISS!" << dec << endl;
    }
    hit_level = -1;
    return vector<int>();
}

bool check_half_zero_pb_l1(const vector<bool> &v, int l, int r)
{
    for (size_t i = l; i < r; i++)
    {
        if (v[i])
            return false;
    }
    return true;
}

vector<bool> vector_or_pb_l1(const vector<bool> &v1, const vector<bool> &v2, int l, int r)
{
    vector<bool> result(r - l);
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = v1[l + i] || v2[l + i];
    }
    return result;
}

bool compare_or_pb_l1(const vector<bool> &x, const vector<bool> &y, int l, int r)
{
    int count = 0;
    for (size_t i = l; i < r; i++)
    {
        if (!x[i] ^ y[i])
            count++;
    }
    if (knob::rb_l1_debug_level >= 1)
    {
        cerr << "count=" << count << ", r=" << r << ", l=" << l << ", thresh=" << knob::rb_l1_or_thresh << endl;
    }
    if (count < (r - l) * knob::rb_l1_or_thresh)
        return false;
    return true;
}

bool compare_accuracy_pb_l1(const vector<bool> &x, const vector<bool> &y, int l, int r)
{
    int count = 0;
    for (size_t i = l; i < r; i++)
    {
        if (!x[i] ^ y[i])
            count++;
    }
    if (knob::rb_l1_debug_level >= 1)
    {
        cerr << "count=" << count << ", r=" << r << ", l=" << l << ", thresh=" << knob::rb_l1_accuracy_thresh << endl;
    }
    if (count < (r - l) * knob::rb_l1_accuracy_thresh)
        return false;
    return true;
}

vector<bool> sub_vector_pb_l1(const vector<bool> &v, int l, int r)
{
    vector<bool> result(r - l);
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = v[l + i];
    }
    return result;
}

void RB_L1::insert_in_pht(const ATRB_L1::Entry &entry, int at_level)
{
    // cout << "insert_in_pht" << endl;
    uint64_t pc = entry.data.pc;
    int offset = entry.data.offset;
    uint64_t region_number = hash_index(entry.key, this->at[at_level].get_index_len());
    uint64_t address = region_number * this->pattern_len[at_level] + entry.data.offset;
    vector<bool> new_pattern = entry.data.pattern;
    vector<bool> old_pattern = entry.data.pattern_prefetch;

    if (old_pattern.empty())
    {
        if (offset < new_pattern.size() / 2)
        {
            if (check_half_zero_pb_l1(new_pattern, new_pattern.size() / 2, new_pattern.size()))
            {
                this->pht[at_level - 1].insert(pc, address, sub_vector_pb_l1(new_pattern, 0, new_pattern.size() / 2));
            }else{
                this->pht[at_level].insert(pc, address, new_pattern);
            }
        }
        else{
            if (check_half_zero_pb_l1(new_pattern, 0, new_pattern.size() / 2)){
                this->pht[at_level - 1].insert(pc, address, sub_vector_pb_l1(new_pattern, new_pattern.size() / 2, new_pattern.size()));
            }else{
                this->pht[at_level].insert(pc, address, new_pattern);
            }
        }
    }
    else
    {
        if (at_level == 0)
        {
            // cout << "at_level = 0" << endl;
            if (compare_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size()))
                this->pht[at_level].insert(pc, address, vector_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size()));
            else
                this->pht[at_level].insert(pc, address, new_pattern);
        }
        else
        {
            if (offset < new_pattern.size() / 2)
            {
#ifdef ACCURACY_LEVELDOWN_RB_L1
                // cout << "1111" << endl;
                if (check_half_zero_pb_l1(new_pattern, new_pattern.size() / 2, new_pattern.size()) || !compare_accuracy_pb_l1(new_pattern, old_pattern, new_pattern.size() / 2, new_pattern.size()))
                {
                    // cout << "2222" << endl;
#else
                if (check_half_zero_pb_l1(new_pattern, new_pattern.size() / 2, new_pattern.size()))
                {
#endif
                    if (compare_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size() / 2))
                        this->pht[at_level - 1].insert(pc, address, vector_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size() / 2));
                    else
                        this->pht[at_level - 1].insert(pc, address, sub_vector_pb_l1(new_pattern, 0, new_pattern.size() / 2));
                    this->pht[at_level].erase(pc, address);
                }
                else
                {
                    // cout << "3333" << endl;
                    if (compare_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size()))
                        this->pht[at_level].insert(pc, address, vector_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size()));
                    else
                        this->pht[at_level].insert(pc, address, new_pattern);
                }
            }
            else
            {
#ifdef ACCURACY_LEVELDOWN_RB_L1
                // cout << "4444" << endl;
                if (check_half_zero_pb_l1(new_pattern, 0, new_pattern.size() / 2) || !compare_accuracy_pb_l1(new_pattern, old_pattern, 0, new_pattern.size() / 2))
                {
                    // cout << "5555" << endl;
#else
                if (check_half_zero_pb_l1(new_pattern, 0, new_pattern.size() / 2))
                {
#endif
                    if (compare_or_pb_l1(new_pattern, old_pattern, new_pattern.size() / 2, new_pattern.size()))
                        this->pht[at_level - 1].insert(pc, address, vector_or_pb_l1(new_pattern, old_pattern, new_pattern.size() / 2, new_pattern.size()));
                    else
                        this->pht[at_level - 1].insert(pc, address, sub_vector_pb_l1(new_pattern, new_pattern.size() / 2, new_pattern.size()));
                    this->pht[at_level].erase(pc, address);
                }
                else
                {
                    // cout << "6666" << endl;
                    if (compare_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size()))
                        this->pht[at_level].insert(pc, address, vector_or_pb_l1(new_pattern, old_pattern, 0, new_pattern.size()));
                    else
                        this->pht[at_level].insert(pc, address, new_pattern);
                }
            }
        }
    }
}

vector<int> RB_L1::vote(const vector<vector<bool>> &x)
{
    if (this->debug_level >= 2)
        cerr << "RB_L1::vote(...)" << endl;
    int n = x.size();
    if (n == 0)
    {
        if (this->debug_level >= 2)
            cerr << "[RB_L1::vote] There are no voters." << endl;
        return vector<int>();
    }
    if (this->debug_level >= 2)
    {
        cerr << "[RB_L1::vote] Taking a vote among:" << endl;
        for (int i = 0; i < n; i += 1)
            cerr << "<" << setw(3) << i + 1 << "> " << rb_l1_pattern_to_string(x[i]) << endl;
    }
    bool pf_flag = false;
    vector<int> res(x[0].size(), 0);
    for (int i = 0; i < n; i += 1)
        // assert((int)x[i].size() == this->pattern_len);
        for (int i = 0; i < x[0].size(); i += 1)
        {
            int cnt = 0;
            for (int j = 0; j < n; j += 1)
                if (x[j][i])
                    cnt += 1;
            double p = 1.0 * cnt / n;
            if (p >= knob::rb_l1_l2c_thresh)
                res[i] = FILL_L1;
            else if (p >= knob::rb_l1_llc_thresh)
                res[i] = FILL_L2;
            else
                res[i] = 0;
            if (res[i] != 0)
                pf_flag = true;
        }
    if (this->debug_level >= 2)
    {
        cerr << "<res> " << rb_l1_pattern_to_string(res) << endl;
    }
    if (!pf_flag)
        return vector<int>();
    return res;
}

/* Base-class virtual function */
void RB_L1::invoke_prefetcher(uint64_t pc, uint64_t addr, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr)
{
    if (debug_level >= 2)
    {
        cerr << "CACHE::l2C_prefetcher_operate(addr=0x" << hex << addr << ", PC=0x" << pc << ", cache_hit=" << dec
             << (int)cache_hit << ", type=" << (int)type << ")" << dec << endl;
    }

    if (type != LOAD)
        return;

    uint64_t block_number = addr >> LOG2_BLOCK_SIZE;

    /* update RB_L1 with most recent LOAD access */
    access(block_number, pc);

    /* issue prefetches */
    prefetch(block_number);

    if (debug_level >= 3)
    {
        log();
        cerr << "=======================================" << dec << endl;
    }
}

void RB_L1::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr)
{
    uint64_t evicted_block_number = evicted_addr >> LOG2_BLOCK_SIZE;

    if (parent->block[set][way].valid == 0)
        return; /* no eviction */

    /* inform all modules of the eviction */
    /* RB_L1ERA: original code was to send eviction signal to RB_L1 in every core
     * modified it to make the signal local */
    eviction(evicted_block_number);
}

void RB_L1::dump_stats()
{
    // print_stats();
}
