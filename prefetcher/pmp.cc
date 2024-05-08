#include <iostream>
#include "cache.h"
#include "champsim.h"
#include "pmp.h"

namespace knob
{
    extern uint32_t pmp_region_size;
    extern uint32_t pmp_pattern_len;
    extern uint32_t pmp_counter_max;
    extern uint32_t pmp_ft_size;
    extern uint32_t pmp_at_size;
    extern uint32_t pmp_ps_size;
    extern float pmp_l1_thresh;
    extern float pmp_l2_thresh;
    extern uint32_t pmp_debug_level;
}

void PMP::init_knobs()
{
}

void PMP::init_stats()
{
}

PMP::PMP(string type, CACHE *cache) : Prefetcher(type), parent(cache),
                                      pattern_len(knob::pmp_pattern_len), ft(knob::pmp_ft_size, knob::pmp_debug_level),
                                      at(knob::pmp_at_size, knob::pmp_pattern_len, knob::pmp_debug_level),
                                      opt(knob::pmp_pattern_len, knob::pmp_counter_max, knob::pmp_debug_level),
                                      ppt(knob::pmp_pattern_len / 2, knob::pmp_counter_max, knob::pmp_debug_level),
                                      ps(knob::pmp_ps_size, knob::pmp_pattern_len, knob::pmp_debug_level), debug_level(knob::pmp_debug_level)
{
    init_knobs();
    init_stats();
}

PMP::~PMP()
{
}

void PMP::print_config()
{
    cout << "pmp_region_size" << knob::pmp_region_size << endl
         << "pmp_pattern_len" << knob::pmp_pattern_len << endl
         << "pmp_counter_max" << knob::pmp_counter_max << endl
         << "pmp_ft_size" << knob::pmp_ft_size << endl
         << "pmp_at_size" << knob::pmp_at_size << endl
         << "pmp_ps_size" << knob::pmp_ps_size << endl
         << "pmp_l1_thresh" << knob::pmp_l1_thresh << endl
         << "pmp_l2_thresh" << knob::pmp_l2_thresh << endl
         << "pmp_debug_level" << knob::pmp_debug_level << endl
         << endl;
}

void PMP::access(uint64_t block_number, uint64_t pc)
{
    if (this->debug_level >= 2)
        cerr << "[PMP] access(block_number=0x" << hex << block_number << ", pc=0x" << pc << ")" << dec << endl;
    uint64_t region_number = block_number / this->pattern_len;
    int region_offset = block_number % this->pattern_len;
    bool success = this->at.set_pattern(region_number, region_offset);
    if (success)
        return;
    FTPMP::Entry *entry = this->ft.find(region_number);
    if (!entry)
    {
        /* trigger access */
        this->ft.insert(region_number, pc, region_offset);
        vector<int> pattern = this->find_in_pht(pc, block_number);
        if (pattern.empty())
        {
            /* nothing to prefetch */
            return;
        }
        /* give pattern to `pf_streamer` */
        // assert((int)pattern.size() == this->pattern_len);
        this->ps.insert(region_number, pattern);
        return;
    }
    if (entry->data.offset != region_offset)
    {
        /* move from filter table to accumulation table */
        uint64_t region_number = hash_index(entry->key, this->ft.get_index_len());
        ATPMP::Entry victim =
            this->at.insert(region_number, entry->data.pc, entry->data.offset);
        this->at.set_pattern(region_number, region_offset);
        this->ft.erase(region_number);
        if (victim.valid)
        {
            /* move from accumulation table to PHT */
            this->insert_in_pht(victim);
        }
    }
}

void PMP::eviction(uint64_t block_number)
{
    if (this->debug_level >= 2)
        cerr << "[PMP] eviction(block_number=" << block_number << ")" << dec << endl;
    /* end of generation: footprint must now be stored in PHT */
    uint64_t region_number = block_number / this->pattern_len;
    this->ft.erase(region_number);
    ATPMP::Entry *entry = this->at.erase(region_number);
    if (entry)
    {
        /* move from accumulation table to PHT */
        this->insert_in_pht(*entry);
    }
}

int PMP::prefetch(uint64_t block_number)
{
    int pf_issued = this->ps.prefetch(parent, block_number);
    if (this->debug_level >= 2)
        cerr << "[PMP::prefetch] pf_issued=" << pf_issued << dec << endl;
    return pf_issued;
}

void PMP::set_debug_level(int debug_level)
{
    this->ft.set_debug_level(debug_level);
    this->at.set_debug_level(debug_level);
    //    this->pht.set_debug_level(debug_level);
    this->ps.set_debug_level(debug_level);
    this->debug_level = debug_level;
}

void PMP::log()
{
    cerr << "Filter Table:" << dec << endl;
    cerr << this->ft.log();

    cerr << "Accumulation Table:" << dec << endl;
    cerr << this->at.log();

    //    cerr << "Pattern History Table:" << dec << endl;
    //    cerr << this->pht.log();

    cerr << "Prefetch Streamer:" << dec << endl;
    cerr << this->ps.log();
}

vector<int> PMP::find_in_pht(uint64_t pc, uint64_t address)
{
    if (this->debug_level >= 2)
    {
        cerr << "[PMP] find_in_pht(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
    }
    int offset = address % this->pattern_len;
    vector<int> opt_pattern = this->opt.extrate(offset);
    vector<int> ppt_pattern = this->ppt.extrate(pc);
    if (opt_pattern.empty() || ppt_pattern.empty())
        return vector<int>();
    vector<int> result(this->pattern_len, 0);
    for (size_t i = 0; i < result.size(); i++)
    {
        if (opt_pattern[i])
        {
            if (ppt_pattern[i / 2])
                result[i] = FILL_L2;
            else
                result[i] = FILL_LLC;
        }
    }
    result = pmp_rotate(result, offset);
    return result;
}

void PMP::insert_in_pht(const ATPMP::Entry &entry)
{
    uint64_t pc = entry.data.pc;
    int offset = entry.data.offset;
    if (this->debug_level >= 2)
    {
        cerr << "[PMP] insert_in_pht(pc=0x" << hex << pc << ", offset=" << dec << offset << ")" << endl;
    }
    vector<bool> opt_pattern = entry.data.pattern;
    opt_pattern = pmp_rotate(opt_pattern, -offset);
    vector<bool> ppt_pattern(this->pattern_len / 2, 0);
    for (size_t i = 0; i < ppt_pattern.size(); i++)
    {
        if (opt_pattern[2 * i] || opt_pattern[2 * i + 1])
            ppt_pattern[i] = true;
    }
    this->opt.merge(offset, opt_pattern);
    this->ppt.merge(pc, ppt_pattern);
}

/* Base-class virtual function */
void PMP::invoke_prefetcher(uint64_t pc, uint64_t addr, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr)
{
   if (debug_level >= 2) {
      cerr << "CACHE::l2C_prefetcher_operate(addr=0x" << hex << addr << ", PC=0x" << pc << ", cache_hit=" << dec
      << (int)cache_hit << ", type=" << (int)type << ")" << dec << endl;
   }

   if (type != LOAD)
   return;

   uint64_t block_number = addr >> LOG2_BLOCK_SIZE;

   /* update PMP with most recent LOAD access */
   access(block_number, pc);

   /* issue prefetches */
   prefetch(block_number);

   if (debug_level >= 3) {
      log();
      cerr << "=======================================" << dec << endl;
   }
}

void PMP::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr) {
   uint64_t evicted_block_number = evicted_addr >> LOG2_BLOCK_SIZE;

   if (parent->block[set][way].valid == 0)
   return; /* no eviction */

   /* inform all sms modules of the eviction */
   /* RBERA: original code was to send eviction signal to PMP in every core
   * modified it to make the signal local */
   eviction(evicted_block_number);
}

void PMP::dump_stats() {
   
}
