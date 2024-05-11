#include <iostream>
#include "Domino.h"
#include "champsim.h"

namespace knob
{
  extern uint32_t Domino_active_stream_size;
  extern uint32_t Domino_degree;
  extern uint32_t Domino_super_entry_size;
  extern uint32_t Domino_debug_level;
}

Domino::Domino(string type, CACHE *cache) : Prefetcher(type), parent(cache),
                                            match_candidate_valid(false),
                                            history_buffer(),
                                            active_stream(knob::Domino_active_stream_size, &history_buffer, knob::Domino_debug_level),
                                            degree(knob::Domino_degree),
                                            super_entry_size(knob::Domino_super_entry_size), debug_level(knob::Domino_debug_level)
{
  init_knobs();
  init_stats();
  last_address = 0;
  match_candidate = nullptr;
  match_candidate_valid = false;
  cout << "Init Domino!" << endl;
  print_config();
}

Domino::~Domino()
{
}

void Domino::print_config()
{
  cout << "Domino_active_stream_size" << knob::Domino_active_stream_size
       << "Domino_super_entry_size" << knob::Domino_super_entry_size
       << "Domino_degree" << knob::Domino_degree
       << "Domino_debug_level" << knob::Domino_debug_level;
}

void Domino::init_knobs()
{
}

void Domino::init_stats()
{
}

bool Domino::match_second_address(uint64_t second_address, vector<uint64_t> &pref_addr)
{
  if (match_candidate_valid)
  {
    if (debug_level >= 2)
    {
      cout << "Candidate content: " << endl;
      match_candidate->print_content();
    }
    uint64_t pointer;
    if (match_candidate->find(second_address, pointer))
    {
      set<uint64_t> stream_address;
      if (debug_level >= 2)
      {
        cout << "Replay::Successfully match 2nd address! Pointer=" << pointer
             << ", 1st_addr=" << hex << history_buffer[pointer - 1]
             << ", 2nd_addr=" << hex << history_buffer[pointer] << endl;
        cout << "Replay::Create stream!" << endl;
      }
      int i;
      for (i = 1; i <= degree; i++)
      {
        if (pointer + i < history_buffer.size())
        {
          pref_addr.emplace_back(history_buffer[pointer + i]);
          stream_address.insert(history_buffer[pointer + i]);
          if (debug_level >= 2)
          {
            cout << "Pointer=" << pointer + i << ", Address=0x" << hex << history_buffer[pointer + i] << endl;
          }
        }
        else
          break;
      }

      active_stream.create_stream(Stream_data(pointer + i, stream_address));

      return true;
    }
  }
  if (debug_level >= 2)
    cout << "Replay::Can't match 2nd address!" << endl;
  return false;
}

bool Domino::seach_first_address(uint64_t first_address, vector<uint64_t> &pref_addr)
{
  if (index_table.find(first_address) != index_table.end())
  {
    match_candidate = &(index_table[first_address]);
    match_candidate_valid = true;
    uint64_t prefetched_addr = match_candidate->get_mru_addr();
    pref_addr.emplace_back(prefetched_addr);
    if (debug_level >= 2)
    {
      cout << "Replay::Successfully match 1st address! address=0x" << hex << first_address << ", mru_address=0x" << hex << prefetched_addr << endl;
      cout << "Candidate content:" << endl;
      match_candidate->print_content();
    }
    return true;
  }
  if (debug_level >= 2)
    cout << "Replay::Can't match 1st address!" << endl;
  match_candidate_valid = false;
  return false;
}

void Domino::invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, vector<uint64_t> &pref_addr)
{
  uint64_t block_address = address >> LOG2_BLOCK_SIZE;
  if (cache_hit && prefetched_address.find(block_address) == prefetched_address.end())
    return;
  if (block_address == last_address)
    return;

  if (debug_level >= 2)
  {
    cout << endl
         << "Domino::access. Block_addr=0x" << hex << block_address << ", pc=0x" << hex << pc << endl;
  }

  // replay
  if (!active_stream.search_stream(block_address, pref_addr))
  {
    if (!match_second_address(block_address, pref_addr))
      seach_first_address(block_address, pref_addr);
  }

  // prefetch
  for (size_t i = 0; i < pref_addr.size(); i++)
  {
    parent->prefetch_line(pc, address, pref_addr[i] << LOG2_BLOCK_SIZE, FILL_L2, 0);
    prefetched_address.insert(pref_addr[i]);
  }

  // record
  history_buffer.emplace_back(block_address);
  if (debug_level >= 2)
  {
    cout << "Record::Insert HB! pointer=" << dec << history_buffer.size() - 1 << endl;
  }
  if (last_address != 0)
  {
    if (index_table.find(last_address) != index_table.end())
    {
      if (debug_level >= 2)
      {
        cout << "Record::Hit IT! last_addr=0x" << hex << last_address << endl;
      }
      index_table[last_address].insert(block_address, history_buffer.size() - 1);
    }
    else
    {
      if (debug_level >= 2)
      {
        cout << "Record::Miss IT! last_addr=0x" << hex << last_address << endl;
      }
      Super_Entry super_entry(last_address, block_address, history_buffer.size() - 1, super_entry_size, debug_level);
      // index_table[last_address] = super_entry;
      index_table.insert(make_pair(last_address, super_entry));
      // cout << "Insert IT!" << endl;
    }
  }
  last_address = block_address;
}

void Domino::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr)
{
  prefetched_address.erase(evicted_addr >> LOG2_BLOCK_SIZE);
}

void Domino::dump_stats()
{
}
