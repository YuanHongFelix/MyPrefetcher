#ifndef ISB_H
#define ISB_H

#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <algorithm>
#include "prefetcher.h"
#include "cache.h"


// #define TU_WAY_COUNT 256
// #define PHY_ADDRESS_ENCODER_SIZE 256
// #define STR_ADDRESS_ENCODER_SIZE 256


using namespace std;
class PrefetchBufferData
{
public:
   uint64_t data;
   bool valid;
};

class PrefetchBuffer{
public:
    PrefetchBuffer(int size) : size(size), next_index(0){
        buffer = new PrefetchBufferData[size];
    }
    ~PrefetchBuffer(){
        delete[]buffer;
    }
    void reset(){
        for(int i = 0; i < size; i++)
            buffer[i].valid = false;
        next_index = 0;
    }
    void add(uint64_t address){
        buffer[next_index].data = address;
        buffer[next_index].valid = true;
        next_index = (next_index + 1) % size;
    }

    void issue(unsigned int i){
        assert(buffer[i].valid);
        buffer[i].valid = false;
    }

    bool get(unsigned int index, uint64_t& address){
        address = buffer[index].data;
        return buffer[index].valid;
    }

private:
    PrefetchBufferData *buffer;
    int size;
    unsigned int next_index;
};


class TrainingUnitEntry{
public:
	// Per entry size equals 64 bits of key, 64 bits of address (virtual 64 bits, phy 48 bits), 10 bits str_addr = 138 bits = 17.25 Bytes 
    uint64_t key;
    uint64_t addr;
    unsigned int str_addr;

    TrainingUnitEntry(){
        reset();
    } 
    void reset(){
        key = 0;
        addr = 0;
        str_addr = 0;
    }  
    TrainingUnitEntry(uint64_t _key){
        key = _key;
        addr = 0;
        str_addr = 0;
    }   
};
typedef std::map<uint64_t, TrainingUnitEntry*> TUCache;


//PS_Entry: 64 bits key + 10 bits str_addr + 1 valid bit + 2 confidence bits = 77 bits.
class PS_Entry {
public:
    unsigned int str_addr;
    bool valid;
    unsigned int confidence;

    PS_Entry() {
	    reset();
    }

    void reset(){
        valid = false;
        str_addr = 0;
        confidence = 0;
    }
    void set(unsigned int addr){
        reset();
        str_addr = addr;
        valid = true;
        confidence = 3;
    }
    int increase_confidence(){
        confidence = (confidence == 3) ? confidence : (confidence + 1);
        return confidence;
    }
    int lower_confidence(){
        confidence = (confidence == 0) ? confidence : (confidence - 1);
        return confidence;
    }
};

//SP_Entry: 10 bits str_addr key + 64 bits phy_addr (we are using virtual) + 1 bit valid = 75 bits
class SP_Entry 
{
public:
    uint64_t phy_addr;
    bool valid;

    void reset(){
        valid = false;
        phy_addr = 0;
    }

    void set(uint64_t addr){
        phy_addr = addr;
        valid = true;
    }
};

class OffChipInfo{
public:
    OffChipInfo(int debug_level = 0):debug_level(debug_level){
        reset();
	    win1k_ps = win10k_ps = win100k_ps = win1m_ps = win1k_sp = win10k_sp = win100k_sp = win1m_sp = 1;
	    total_access_counter_ps = total_access_counter_sp = 0;
    }
    
    void reset(){
        ps_map.clear();
        sp_map.clear();
    }
    bool get_structural_address(uint64_t phy_addr, unsigned int& str_addr);
    bool get_physical_address(uint64_t& phy_addr, unsigned int str_addr);
    void update(uint64_t phy_addr, unsigned int str_addr);
    // void update_physical(uint64_t phy_addr, unsigned int str_addr);
    // void update_structural(uint64_t phy_addr, unsigned int str_addr);
    void invalidate(uint64_t phy_addr, unsigned int str_addr);
    int increase_confidence(uint64_t phy_addr);
    int lower_confidence(uint64_t phy_addr);
    void print_stats();

private:
    int debug_level = 0;
    map<uint64_t,PS_Entry*> ps_map;
    map<unsigned int,SP_Entry*> sp_map;

    // Stats
    map<uint64_t, uint64_t> ps_map_access_frequency;
	map<unsigned int, uint64_t> sp_map_access_frequency;
	
    //Windows within which we are trying to capture the number of unique accesses to ps_map and sp_map. 
	uint64_t win1k_ps, win10k_ps, win100k_ps, win1m_ps, total_access_counter_ps, win1k_sp, win10k_sp, win100k_sp, win1m_sp, total_access_counter_sp;

	set<uint64_t> win1k_ps_access_keys, win10k_ps_access_keys, win100k_ps_access_keys, win1m_ps_access_keys;
	set<unsigned int> win1k_sp_access_keys, win10k_sp_access_keys, win100k_sp_access_keys, win1m_sp_access_keys;

	//Not total accesses, but unique accesses.
	map<uint64_t, uint64_t> win1k_ps_map_accesses, win10k_ps_map_accesses, win100k_ps_map_accesses, win1m_ps_map_accesses, win1k_sp_map_accesses, win10k_sp_map_accesses, win100k_sp_map_accesses, win1m_sp_map_accesses;
};

class ISB : public Prefetcher{
public:
    ISB(string type, CACHE *cache);
    ~ISB();
    void invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr);
    void register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr);
    void dump_stats();
    void print_config();

private:
    unsigned int train(unsigned int str_addr_A, uint64_t phy_addr_B);
    vector<uint64_t> predict(uint64_t trigger_phy_addr, unsigned int trigger_str_addr, uint64_t ip);
    bool access_training_unit(uint64_t key, uint64_t& last_phy_addr, unsigned int& last_str_addr, uint64_t next_addr);
    void update_training_unit(uint64_t key, uint64_t addr, unsigned int str_addr);
    unsigned int assign_structural_addr();
    // bool get_structural_address( uint64_t addr, unsigned int& str_addr);

   /*======================*/
    CACHE *parent;
    TUCache training_unit; 
    OffChipInfo off_chip_info;
    uint64_t alloc_counter;
    uint64_t last_address;

    int debug_level;
    int degree; //8
    int stream_max_lenth; //1024
    int stream_max_lenth_bits; //10
    bool is_restrict_region;

    //no use
    // PrefetchBuffer prefetch_buffer;

    // Stat
    uint64_t exceed_stream_alloc = 0;
    uint64_t stream_divergence_count = 0;
    unsigned int total_access = 0;
    unsigned int predictions = 0;
    unsigned int no_prediction = 0;
    unsigned int stream_end = 0;
    unsigned int no_translation = 0;
    unsigned int reuse = 0;
};

#endif /* ISB_H */