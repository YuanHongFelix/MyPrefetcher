#include <iostream>
#include "champsim.h"
#include "isb.h"
#include "cache.h"

#define TRAIN_ON_CACHE_MISSES
#define L2_PREFETCH_FILL_LEVEL FILL_L2

namespace knob
{
    extern bool ISB_is_restrict_region;
    extern uint32_t ISB_stream_max_lenth;
    extern uint32_t ISB_stream_max_lenth_bits;
    extern uint32_t ISB_degree;
    extern uint32_t ISB_debug_level;
}

bool OffChipInfo::get_structural_address(uint64_t phy_addr, unsigned int &str_addr)
{
    if (debug_level >= 2)
    {
        cout << "OffChipInfo::get_structural_address. Search phy_addr=0x" << hex << phy_addr << endl;
    }
    map<uint64_t, PS_Entry *>::iterator ps_iter = ps_map.find(phy_addr);
    if (ps_iter == ps_map.end())
    {
        if (debug_level >= 2)
        {
            cout << "OffChipInfo::get_structural_address. No found!" << endl;
        }
        return false;
    }
    else
    {
        if (ps_iter->second->valid)
        {
            str_addr = ps_iter->second->str_addr;
            ps_map_access_frequency[phy_addr] = ps_map_access_frequency[phy_addr] + 1;

            win1k_ps_access_keys.insert(phy_addr);
            win10k_ps_access_keys.insert(phy_addr);
            win100k_ps_access_keys.insert(phy_addr);
            win1m_ps_access_keys.insert(phy_addr);

            total_access_counter_ps++;

            if (total_access_counter_ps % 1000 == 0)
            {
                win1k_ps_map_accesses.insert(pair<uint64_t, uint64_t>(win1k_ps, win1k_ps_access_keys.size()));
                win1k_ps++;
                win1k_ps_access_keys.clear();
            }
            if (total_access_counter_ps % 10000 == 0)
            {
                win10k_ps_map_accesses.insert(pair<uint64_t, uint64_t>(win10k_ps, win10k_ps_access_keys.size()));
                win10k_ps++;
                win10k_ps_access_keys.clear();
            }
            if (total_access_counter_ps % 100000 == 0)
            {
                win100k_ps_map_accesses.insert(pair<uint64_t, uint64_t>(win100k_ps, win100k_ps_access_keys.size()));
                win100k_ps++;
                win100k_ps_access_keys.clear();
            }
            if (total_access_counter_ps % 1000000 == 0)
            {
                win1m_ps_map_accesses.insert(pair<uint64_t, uint64_t>(win1m_ps, win1m_ps_access_keys.size()));
                win1m_ps++;
                win1m_ps_access_keys.clear();
            }
            if (debug_level >= 2)
            {
                cout << "OffChipInfo::get_structural_address. Found! str_addr=" << dec << str_addr << endl;
            }

            return true;
        }
        else
        {
            if (debug_level >= 2)
            {
                cout << "OffChipInfo::get_structural_address. No valid!" << endl;
            }
            return false;
        }
    }
}

bool OffChipInfo::get_physical_address(uint64_t &phy_addr, unsigned int str_addr)
{
    if (debug_level >= 2)
    {
        cout << "OffChipInfo::get_physical_address. Search str_addr=" << dec << str_addr << endl;
    }
    std::map<unsigned int, SP_Entry *>::iterator sp_iter = sp_map.find(str_addr);
    if (sp_iter == sp_map.end())
    {
        if (debug_level >= 2)
        {
            cout << "OffChipInfo::get_physical_address. No found!" << endl;
        }
        return false;
    }
    else
    {
        if (sp_iter->second->valid)
        {
            phy_addr = sp_iter->second->phy_addr;
            sp_map_access_frequency[str_addr] = sp_map_access_frequency[str_addr] + 1;

            win1k_sp_access_keys.insert(str_addr);
            win10k_sp_access_keys.insert(str_addr);
            win100k_sp_access_keys.insert(str_addr);
            win1m_sp_access_keys.insert(str_addr);

            total_access_counter_sp++;

            if (total_access_counter_sp % 1000 == 0)
            {
                win1k_sp_map_accesses.insert(pair<uint64_t, uint64_t>(win1k_sp, win1k_sp_access_keys.size()));
                win1k_sp++;
                win1k_sp_access_keys.clear();
            }
            if (total_access_counter_sp % 10000 == 0)
            {
                win10k_sp_map_accesses.insert(pair<uint64_t, uint64_t>(win10k_sp, win10k_sp_access_keys.size()));
                win10k_sp++;
                win10k_sp_access_keys.clear();
            }
            if (total_access_counter_sp % 100000 == 0)
            {
                win100k_sp_map_accesses.insert(pair<uint64_t, uint64_t>(win100k_sp, win100k_sp_access_keys.size()));
                win100k_sp++;
                win100k_sp_access_keys.clear();
            }
            if (total_access_counter_sp % 1000000 == 0)
            {
                win1m_sp_map_accesses.insert(pair<uint64_t, uint64_t>(win1m_sp, win1m_sp_access_keys.size()));
                win1m_sp++;
                win1m_sp_access_keys.clear();
            }
            if (debug_level >= 2)
            {
                cout << "OffChipInfo::get_physical_address. Found! phy_addr=" << hex << phy_addr << endl;
            }
            return true;
        }
        else
        {
            if (debug_level >= 2)
            {
                cout << "OffChipInfo::get_physical_address. No valid!" << endl;
            }
            return false;
        }
    }
}

void OffChipInfo::update(uint64_t phy_addr, unsigned int str_addr)
{
    if (debug_level >= 2)
    {
        cout << "OffChipInfo::update, phy_addr=0x" << hex << phy_addr << ", str_addr=" << dec << str_addr << endl;
    }

    // PS Map Update
    std::map<uint64_t, PS_Entry *>::iterator ps_iter = ps_map.find(phy_addr);
    if (ps_iter == ps_map.end())
    {
        PS_Entry *ps_entry = new PS_Entry();
        ps_map[phy_addr] = ps_entry;
        ps_map[phy_addr]->set(str_addr);
        ps_map_access_frequency[phy_addr] = 0;
    }
    else
    {
        ps_iter->second->set(str_addr);
    }

    // SP Map Update
    std::map<unsigned int, SP_Entry *>::iterator sp_iter = sp_map.find(str_addr);
    if (sp_iter == sp_map.end())
    {
        SP_Entry *sp_entry = new SP_Entry();
        sp_map[str_addr] = sp_entry;
        sp_map[str_addr]->set(phy_addr);
        sp_map_access_frequency[str_addr] = 0;
    }
    else
    {
        sp_iter->second->set(phy_addr);
    }
}

// void OffChipInfo::update_physical(uint64_t phy_addr, unsigned int str_addr){
//     if (debug_level >= 2){
//         cout << "OffChipInfo::update_physical, phy_addr=0x" << hex << phy_addr <<", str_addr=" << dec <<str_addr << endl;
//     }

//     //PS Map Update
//     std::map<uint64_t, PS_Entry*>::iterator ps_iter = ps_map.find(phy_addr);
//     if(ps_iter == ps_map.end()){
//         PS_Entry* ps_entry = new PS_Entry();
//         ps_map[phy_addr] = ps_entry;
//         ps_map[phy_addr]->set(str_addr);
//     }else{
//         ps_iter->second->set(str_addr);
//     }
// }

// void OffChipInfo::update_structural(uint64_t phy_addr, unsigned int str_addr){
//     if (debug_level >= 2){
//         cout << "OffChipInfo::update_structure, phy_addr=0x" << hex << phy_addr <<", str_addr=" << dec <<str_addr << endl;
//     }

//     //SP Map Update
//     std::map<unsigned int, SP_Entry*>::iterator sp_iter = sp_map.find(str_addr);
//     if(sp_iter == sp_map.end()){
//         SP_Entry* sp_entry = new SP_Entry();
//         sp_map[str_addr] = sp_entry;
//         sp_map[str_addr]->set(phy_addr);
//     }else{
//         sp_iter->second->set(phy_addr);
//     }
// }

void OffChipInfo::invalidate(uint64_t phy_addr, unsigned int str_addr)
{
    if (debug_level >= 2)
    {
        cout << "OffChipInfo::invalidate, phy_addr=0x" << hex << phy_addr << ", str_addr=" << dec << str_addr << endl;
    }

    // PS Map Invalidate
    std::map<uint64_t, PS_Entry *>::iterator ps_iter = ps_map.find(phy_addr);
    if (ps_iter != ps_map.end())
    {
        ps_iter->second->reset();
        delete ps_iter->second;
        ps_map.erase(ps_iter);
    }
    else
    {
        // TODO TBD
    }

    // SP Map Invalidate
    std::map<unsigned int, SP_Entry *>::iterator sp_iter = sp_map.find(str_addr);
    if (sp_iter != sp_map.end())
    {
        sp_iter->second->reset();
        delete sp_iter->second;
        sp_map.erase(sp_iter);
    }
    else
    {
        // TODO TBD
    }
}

int OffChipInfo::increase_confidence(uint64_t phy_addr)
{
    if (debug_level >= 2)
    {
        cout << "OffChipInfo::increase_confidence, phy_addr=0x" << hex << phy_addr << endl;
    }
    std::map<uint64_t, PS_Entry *>::iterator ps_iter = ps_map.find(phy_addr);
    if (ps_iter != ps_map.end())
    {
        return ps_iter->second->increase_confidence();
    }
    else
    {
        assert(0);
        return -1;
    }
}

int OffChipInfo::lower_confidence(uint64_t phy_addr)
{
    if (debug_level >= 2)
    {
        cout << "OffChipInfo::lower_confidence, phy_addr=0x" << hex << phy_addr << endl;
    }

    std::map<uint64_t, PS_Entry *>::iterator ps_iter = ps_map.find(phy_addr);
    if (ps_iter != ps_map.end())
    {
        return ps_iter->second->lower_confidence();
    }
    else
    {
        assert(0);
        return -1;
    }
}

void OffChipInfo::print_stats() {}

unsigned int ISB::train(unsigned int str_addr_A, uint64_t phy_addr_B)
{
    // Algorithm for training correlated pair (A,B)
    // Step 2a : If SA(A)+1 does not exist, assign B SA(A)+1
    // Step 2b : If SA(A)+1 exists, copy the stream starting at S(A)+1 and then assign B SA(A)+1
    if (debug_level >= 2)
        std::cout << "ISB::train. str_addr(A)=" << dec << str_addr_A << ", phy_addr(B)=0x" << hex << phy_addr_B << endl;
    unsigned int str_addr_B;
    bool str_addr_B_exists = off_chip_info.get_structural_address(phy_addr_B, str_addr_B);
    if (str_addr_B_exists)
    {
        if (str_addr_B == str_addr_A + 1)
        {
            // if(str_addr_B % stream_max_lenth == (str_addr_A + 1) % stream_max_lenth){
            int confidence = off_chip_info.increase_confidence(phy_addr_B);
            if (debug_level >= 2)
            {
                std::cout << "ISB::train. str_addr(B) exist, confidence++. conf=" << confidence << std::endl;
            }
            return str_addr_B;
        }
        else
        {
            int confidence = off_chip_info.lower_confidence(phy_addr_B);
            if (debug_level >= 2)
            {
                std::cout << "ISB::train. str_addr(B) exist, confidence--. conf=" << confidence << std::endl;
            }
            if (confidence > 0)
                return str_addr_B;

            off_chip_info.invalidate(phy_addr_B, str_addr_B);
            str_addr_B_exists = false;
        }
    }

    assert(!str_addr_B_exists);

    // Handle stream divergence

    // If S(A) is at a stream boundary return, we don't need to worry about B because it is as good as a stream start
    if ((str_addr_A + 1) % stream_max_lenth == 0)
    {
        if (debug_level >= 2)
        {
            cout << "ISB::train. str_addr(A) is boundary!" << endl;
        }
        exceed_stream_alloc += 1;
        str_addr_B = assign_structural_addr();
        off_chip_info.update(phy_addr_B, str_addr_B);
        return str_addr_B;
    }

    // check is S(A)+1 has been assigned?
    uint64_t phy_addr_Aplus1;
    bool phy_addr_Aplus1_exists = off_chip_info.get_physical_address(phy_addr_Aplus1, str_addr_A + 1);
    if (phy_addr_Aplus1_exists)
    {
        // directly overwrite!
        // eg. ACDE AB to ABDE
        if (debug_level >= 2)
        {
            cout << "ISB::train. str_addr(A+1) has existed!" << endl;
        }
        stream_divergence_count++;
        off_chip_info.invalidate(phy_addr_Aplus1, str_addr_A + 1);
    }

    // lyq: assign S(B) = S(A)+1
    str_addr_B = str_addr_A + 1;
    if (debug_level >= 2)
    {
        std::cout << "ISB::train. Assign str_addr(B)=" << dec << str_addr_B << std::endl;
    }
    off_chip_info.update(phy_addr_B, str_addr_B);
    return str_addr_B;

    // #define CFIX
    //  #ifdef CFIX
    //      if(phy_addr_Aplus1_exists)
    //          stream_divergence_count++;
    //          while(phy_addr_Aplus1_exists){
    //              if (debug_level >= 2){
    //                  std::cout << "-----S(A)+1 : " << phy_addr_Aplus1 << std::endl;
    //              }
    //              i++;
    //              if((str_addr_A + i) % stream_max_lenth == 0)
    //              {
    //                  stream_divergence_new_stream++;
    //                  str_addr_B = assign_structural_addr();
    //                  break;
    //              }
    //              phy_addr_Aplus1_exists = off_chip_info.get_physical_address(phy_addr_Aplus1, str_addr_A + i);
    //              // oci.reassign_stream(str_addr_A+1, assign_structural_addr()); //TODO TBD. Should we re-assign??
    //          }
    //          //ACDE AB to ACDEB
    //          if(!phy_addr_Aplus1_exists)
    //              str_addr_B = str_addr_A + i;
    //  #else
    //      if(phy_addr_Aplus1_exists)
    //      {
    //          //Old solution: Nothing fancy, just assign a new address
    //          stream_divergence_count++;
    //          if(invalidated)
    //              return str_addr_B;
    //          else
    //              str_addr_B = assign_structural_addr();
    //      }else
    //          str_addr_B = str_addr_A + 1;
    //  #endif
}

vector<uint64_t> ISB::predict(uint64_t trigger_phy_addr, unsigned int trigger_str_addr, uint64_t ip)
{
    if (debug_level >= 2)
        std::cout << "ISB::predict. pc=0x" << hex << ip << ", phy_addr=0x" << hex << trigger_phy_addr << ", str_addr=" << dec << trigger_str_addr << std::endl;

    uint64_t candidate_phy_addr;
    vector<uint64_t> candidates;
    candidates.clear();

    if (!is_restrict_region)
    {
        int lookahead = 1;
        int ideal = 0;
        for (int i = 0; i < stream_max_lenth; i++)
        {
            if (ideal >= degree)
                break;
            uint64_t str_addr_candidate = trigger_str_addr + lookahead + i;
            if (str_addr_candidate % stream_max_lenth == 0)
            {
                stream_end++;
                break;
            }
            bool ret = off_chip_info.get_physical_address(candidate_phy_addr, str_addr_candidate);
            if (ret)
            {
                ideal++;
                candidates.push_back(candidate_phy_addr);
            }
            else
                no_translation++;
        }
    }
    else
    {
        int num_prefetched = 0;
        for (int i = 0; i < stream_max_lenth; i++)
        {
            uint64_t str_addr_candidate = ((trigger_str_addr >> stream_max_lenth_bits) << stream_max_lenth_bits) + i;

            if (str_addr_candidate == trigger_str_addr)
                continue;

            bool ret = off_chip_info.get_physical_address(candidate_phy_addr, str_addr_candidate);
            if (ret)
            // if(ret && ((candidate_phy_addr >> 12) == (trigger_phy_addr >> 12)) )
            {
                candidates.push_back(candidate_phy_addr);

                if (num_prefetched >= degree)
                    break;
            }
        }
    }

    return candidates;
}

bool ISB::access_training_unit(uint64_t key, uint64_t &last_phy_addr, unsigned int &last_str_addr, uint64_t next_addr)
{
    if (debug_level >= 2)
    {
        cout << "ISB::access_training_unit. pc=0x" << hex << key << endl;
    }
    bool pair_found = true;

    if (training_unit.find(key) == training_unit.end())
    {
        if (debug_level >= 2)
        {
            cout << "ISB::access_training_unit. No found!" << endl;
        }
        TrainingUnitEntry *new_training_entry = new TrainingUnitEntry;
        assert(new_training_entry);
        new_training_entry->reset();
        training_unit[key] = new_training_entry;
        pair_found = false;
    }
    else
    {
        if (debug_level >= 2)
        {
            cout << "ISB::access_training_unit. Found!" << endl;
        }
    }
    assert(training_unit.find(key) != training_unit.end());
    TrainingUnitEntry *curr_training_entry = training_unit.find(key)->second;
    assert(curr_training_entry != NULL);
    last_str_addr = curr_training_entry->str_addr;
    last_phy_addr = curr_training_entry->addr;
    uint64_t last_addr = curr_training_entry->addr;
    if (last_addr == next_addr)
    { // A=B
        if (debug_level >= 2)
        {
            cout << "ISB::access_training_unit. The same to last addr!" << endl;
        }
        return false;
    }

    return pair_found;
}

void ISB::update_training_unit(uint64_t key, uint64_t addr, unsigned int str_addr)
{
    if (debug_level >= 2)
    {
        std::cout << "ISB::updated_training_unit, pc=0x" << std::hex << key << ", phy_addr=0x" << addr << ", str_addr=" << std::dec << str_addr << std::endl;
    }
    assert(training_unit.find(key) != training_unit.end());
    TrainingUnitEntry *curr_training_entry = training_unit.find(key)->second;
    assert(curr_training_entry);
    curr_training_entry->addr = addr;
    curr_training_entry->str_addr = str_addr;
}

// bool ISB::get_structural_address( uint64_t addr, unsigned int& str_addr)
// {
//     return off_chip_info.get_structural_address(addr, str_addr);
// }

unsigned int ISB::assign_structural_addr()
{
    alloc_counter += stream_max_lenth;
    if (debug_level >= 2)
        std::cout << "ISB::assign_structural_addr: " << dec << alloc_counter << std::endl;

    return ((unsigned int)alloc_counter);
}

ISB::ISB(string type, CACHE *cache) : Prefetcher(type), parent(cache),
                                      off_chip_info(knob::ISB_debug_level),
                                      stream_max_lenth(knob::ISB_stream_max_lenth), stream_max_lenth_bits(knob::ISB_stream_max_lenth_bits),
                                      is_restrict_region(knob::ISB_is_restrict_region), degree(knob::ISB_degree), debug_level(knob::ISB_debug_level)
{
    alloc_counter = 0;
    last_address = 0;
    cout << "Init ISB!" << endl;
    print_config();
}

void ISB::print_config()
{
    cout << "ISB_stream_max_lenth " << knob::ISB_stream_max_lenth << endl
         << "ISB_stream_max_lenth_bits " << knob::ISB_stream_max_lenth_bits << endl
         << "ISB_is_restrict_region " << knob::ISB_is_restrict_region << endl
         << "ISB_degree " << knob::ISB_degree << endl
         << "ISB_debug_level " << knob::ISB_debug_level << endl;
};

void ISB::dump_stats(){};

void ISB::invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr)
{
    if (type != LOAD)
        return;

    // #ifdef TRAIN_ON_CACHE_MISSES
    //     if(cache_hit)
    //     {
    //         return;
    //     }
    // #endif

    // #ifdef CRITICAL_PREFETCH_L2
    //  	if(!critical_ip_flag)
    // 	{
    // 		//cout << "Returning from ISB Operate - non-critical IP." << endl;
    // 		return;
    // 	}
    // #endif

    uint64_t addr_B = address >> LOG2_BLOCK_SIZE;
    uint64_t key = pc;

    if (addr_B == last_address)
        return;
    last_address = addr_B;

    total_access++;

    if (debug_level >= 2)
        std::cout << "ISB::access. Address=0x" << std::hex << addr_B << ", pc=0x" << std::hex << key << std::endl;

    unsigned int str_addr_B = 0;
    bool str_addr_B_exists = off_chip_info.get_structural_address(addr_B, str_addr_B);

    if (str_addr_B_exists)
    {
        vector<uint64_t> candidates = predict(addr_B, str_addr_B, pc);
        unsigned int num_prefetched = 0;
        for (unsigned int i = 0; i < candidates.size(); i++)
        {
            // int ret = parent->prefetch_line(pc, address, candidates[i] << LOG2_BLOCK_SIZE, L2_PREFETCH_FILL_LEVEL, 0);
            pref_addr.emplace_back(candidates[i] << LOG2_BLOCK_SIZE);
            // if (ret == 1)
            // {
            if (debug_level >= 2)
            {
                cout << "ISB::prefetch_line. phy_addr=0x" << hex << candidates[i] << endl;
            }
            predictions++;
            num_prefetched++;
            // }
            if (num_prefetched >= degree)
                break;
        }
    }
    else
        no_prediction++;

    unsigned int str_addr_A;
    uint64_t addr_A;
    if (access_training_unit(key, addr_A, str_addr_A, addr_B))
    {
        if (debug_level >= 2)
            std::cout << "ISB::Consider pair: str_addr(A)=" << dec << str_addr_A << ", phy_addr(B)=0x" << hex << addr_B << ". pc=0x" << hex << key << endl;

        if (str_addr_A == 0)
        { // when is this condition true? When this is the 2nd access to the pc
            str_addr_A = assign_structural_addr();
            off_chip_info.update(addr_A, str_addr_A);
        }
        str_addr_B = train(str_addr_A, addr_B);
    }

    update_training_unit(key, addr_B, str_addr_B);

    return;
}

void ISB::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr){};