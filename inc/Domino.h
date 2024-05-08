#ifndef DOMINO_H
#define DOMINO_H

#include <vector>
#include "prefetcher.h"
#include "cache.h"
#include <map>
#include <set>
using namespace std;

class Super_Entry
{
    struct Entry
    {
        bool valid;
        uint64_t second_address;
        uint64_t pointer;
        Entry(bool valid = false, uint64_t second_address = 0, uint64_t pointer = 0) : valid(valid), second_address(second_address), pointer(pointer){};
    };

    vector<Entry> data;
    vector<int> lru;
    uint64_t t = 1;
    uint64_t first_address;
    uint64_t mru_address;
    uint64_t mru_point;
    int debug_level;

    int select_victim()
    {
        return min_element(lru.begin(), lru.end()) - lru.begin();
    }
    void set_mru(int index)
    {
        lru[index] = this->t++;
    }

public:
    Super_Entry(uint64_t first_address = 0, uint64_t second_address = 0, uint64_t point = 0, int size = 0, int debug_level = 0)
        : data(size, Entry()), lru(size, 0), debug_level(debug_level),
          mru_address(second_address), mru_point(point)
    {
        data[0] = Entry(true, second_address, point);
        set_mru(0);
        mru_address = second_address;
        mru_point = point;
    }
    void insert(uint64_t address, uint64_t point)
    {
        int index = select_victim();
        data[index] = Entry(true, address, point);
        set_mru(index);
        mru_address = address;
        mru_point = point;
    }
    bool find(uint64_t address, uint64_t &pointer)
    {
        for (size_t i = 0; i < data.size(); i++)
        {
            if (data[i].valid && data[i].second_address == address)
            {
                pointer = data[i].pointer;
                set_mru(i);
                return true;
            }
        }
        return false;
    }
    uint64_t get_mru_addr()
    {
        return mru_address;
    }
    void print_content()
    {
        for (size_t i = 0; i < data.size(); i++)
        {
            if (data[i].valid)
                cout << "address=0x" << hex << data[i].second_address << ", pointer=" << dec << data[i].pointer << endl;
        }
    }
};

class Stream_data
{
public:
    uint64_t pointer;
    set<uint64_t> prefetched_addr;
    Stream_data(){};
    Stream_data(uint64_t pointer, set<uint64_t> prefetched_addr) : pointer(pointer), prefetched_addr(prefetched_addr){};
};

class Active_stream
{
    vector<Stream_data> stream;
    vector<int> lru;
    uint64_t t = 1;
    int debug_level;
    vector<uint64_t> *history_buffer;
    int select_victim()
    {
        return min_element(lru.begin(), lru.end()) - lru.begin();
    }
    void set_mru(int index)
    {
        lru[index] = this->t++;
    }

public:
    Active_stream(int size, vector<uint64_t> *HBP, int debug_level = 0)
        : stream(size), lru(size, 0),
          history_buffer(HBP), debug_level(debug_level){};
    void create_stream(Stream_data data)
    {
        int index = select_victim();
        stream[index] = data;
        set_mru(index);
    }
    bool search_stream(uint64_t address, vector<uint64_t> &pref_addr)
    {
        for (size_t i = 0; i < stream.size(); i++)
        {
            if (stream[i].prefetched_addr.count(address) > 0)
            {
                stream[i].prefetched_addr.erase(address);
                stream[i].pointer++;
                uint64_t new_prefetch_addr = (*history_buffer)[stream[i].pointer];
                pref_addr.emplace_back(new_prefetch_addr);
                stream[i].prefetched_addr.insert(new_prefetch_addr);
                set_mru(i);
                if (debug_level >= 2)
                {
                    cout << "Stream::Hit! Continue prefetch! pointer=" << dec << stream[i].pointer << ", address=0x" << hex << new_prefetch_addr << endl;
                }
                return true;
            }
        }
        return false;
    }
};

class Domino : public Prefetcher
{
public:
    Domino(string type, CACHE *cache);
    ~Domino();
    void invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, vector<uint64_t> &pref_addr);
    void register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr);
    void dump_stats();
    void print_config();

private:
    void init_knobs();
    void init_stats();
    bool match_second_address(uint64_t second_address, vector<uint64_t> &pref_addr);
    bool seach_first_address(uint64_t first_address, vector<uint64_t> &pref_addr);

    vector<uint64_t> history_buffer;
    uint64_t last_address;
    Super_Entry *match_candidate;
    bool match_candidate_valid;
    map<uint64_t, Super_Entry> index_table;
    Active_stream active_stream;

    set<uint64_t> prefetched_address;
    CACHE *parent = NULL;

    int super_entry_size;
    int degree;
    int debug_level;
};

#endif /* DOMINO_H */
