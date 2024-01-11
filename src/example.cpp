#include <exception>
#include <vector>
#include <memory>
#include <random>
#include <functional>
#include <iostream>
#include <chrono>
#include <array>
#include <numeric>
#include <map>
#include <string>
#include "avl_fastmap.h"

template <class Executable>
auto timeit(Executable exe) -> size_t{

    using namespace std::chrono;
    auto s  = high_resolution_clock::now();
    exe();
    auto l  = duration_cast<milliseconds>(high_resolution_clock::now() - s).count();

    return l;
}

class MemoryManager: public virtual dg::avl_fastmap::memory::Allocatable,
                     public virtual dg::avl_fastmap::memory::CharLaunderable{

    private:    

        std::unique_ptr<char[]> buf;
        size_t head;

    public:

        MemoryManager(std::unique_ptr<char[]> buf, size_t head): buf(std::move(buf)), head(head){}

        char * malloc(size_t sz){

            return static_cast<char *>(std::malloc(sz));
        }

        void free(void * ptr) noexcept{

            std::free(ptr);
        }

        char * launder(void * ptr) noexcept{

            return static_cast<char *>(ptr);
        }
};

auto randomize(const size_t SZ, size_t val_sz) -> std::vector<std::pair<uint64_t, std::pair<const char *, uint32_t>>>{
    
    auto sz_rand_dev = std::bind(std::uniform_int_distribution<uint32_t>{1u, val_sz}, std::mt19937{});
    auto rs = std::vector<std::pair<uint64_t, std::pair<const char *, uint32_t>>>{};

    for (size_t i = 0; i < SZ; ++i){
        auto buf_sz = sz_rand_dev();
        rs.push_back({i * 2 + 1, {(const char *)std::malloc(buf_sz), buf_sz}});
    }

    return rs;
} 

auto extract_keys(const std::vector<std::pair<uint64_t, std::pair<const char *, uint32_t>>>& data){

    auto keys = std::vector<uint64_t>(data.size());
    auto extractor = [](const auto& e){return e.first;};
    std::transform(data.begin(), data.end(), keys.begin(), extractor);

    return keys;
}

using data_type = std::vector<std::pair<uint64_t, std::pair<const char *, uint32_t>>>;

auto random_split(const data_type& vec) -> std::pair<data_type, data_type>{

    data_type lhs{};
    data_type rhs{};

    for (size_t i = 0; i < vec.size(); ++i){
        if (i % 2 == 0){
            rhs.push_back(vec[i]);
        } else{
            lhs.push_back(vec[i]);
        }
    }

    return {std::move(lhs), std::move(rhs)};
}

void insert(dg::avl_fastmap::model::Node *& avl, std::unordered_map<uint64_t, std::pair<const char *, uint32_t>>& mmap, const data_type& inserting_data, MemoryManager& mem_manager){

    avl = dg::avl_fastmap::sorted_insert(avl, inserting_data, mem_manager);
    
    for (const auto& e: inserting_data){
        mmap[e.first] = e.second;
    }
}

void del(dg::avl_fastmap::model::Node *& avl, std::unordered_map<uint64_t, std::pair<const char *, uint32_t>>& mmap, const data_type& deleting_data, MemoryManager& mem_manager){

    auto keys   = extract_keys(deleting_data);
    std::sort(keys.begin(), keys.end());

    for (auto& e: keys){
        // std::cout << e << std::endl;
        // avl = dg::avl_fastmap::del(avl, e, mem_manager);
        mmap.erase(e);
    }

    avl = dg::avl_fastmap::sorted_del(avl, keys, mem_manager);
}

void integrity_check(dg::avl_fastmap::model::Node *& avl, std::unordered_map<uint64_t, std::pair<const char *, uint32_t>>& mmap, MemoryManager& mem_manager){

    static auto rand_dev = std::bind(std::uniform_int_distribution<size_t>{}, std::mt19937{}); 

    if (mmap.size() != dg::avl_fastmap::size(avl)){
        std::cout << mmap.size() << "<>" << dg::avl_fastmap::size(avl) << std::endl;
        std::cout << "mayday" << std::endl;
    }

    if (mmap.size() == 0){
        return;
    }

    data_type data{};
    std::vector<std::optional<std::pair<char *, uint32_t>>> mmapped{};
    size_t popcount = rand_dev() % mmap.size(); 

    for (const auto& e: mmap){
        if (popcount == 0){
            break;
        }

        data.push_back(e);
        --popcount; 
    }
    
    auto keys = extract_keys(data);
    std::sort(keys.begin(), keys.end());
    // std::sort(data.begin(), data.end(), [&](const auto& lhs, const auto& rhs){return lhs.first < rhs.first;});
    dg::avl_fastmap::std_sorted_find(avl, keys, mmapped, mem_manager);

    for (size_t i = 0; i < keys.size(); ++i){
        
        if (mmapped[i]->second != mmap[keys[i]].second || std::memcmp(mmapped[i]->first, mmap[keys[i]].first, mmapped[i]->second) != 0){
            std::cout << "mayday" << std::endl;
        }
    }

    size_t iter_sz = 0u;

    for (auto iter = dg::avl_fastmap::begin(avl, mem_manager); iter != dg::avl_fastmap::end(); ++iter){

        auto cur = *iter;
        iter_sz++;    
        if (mmap.find(cur.first) == mmap.end()){
            std::cout << "mayday" << std::endl;
        }

        if (cur.second.second != mmap[cur.first].second || std::memcmp(cur.second.first, mmap[cur.first].first, cur.second.second) != 0){
            std::cout << "mayday" << std::endl;
        } 
    }

    if (iter_sz != mmap.size()){
        std::cout << "mayday" << std::endl;
    }
}

int main(){

    using namespace dg::avl_fastmap; 

    const size_t SZ     = 1 << 20;
    const size_t VAL_SZ = 1 << 12; 
    auto allocator = MemoryManager{nullptr, 0u};
    auto data           = randomize(SZ, VAL_SZ);
    auto inserted_data  = decltype(data){};
    auto mmap           = std::unordered_map<uint64_t, std::pair<const char *, uint32_t>>{}; 
    auto root           = make();

    while (data.size() > 1){

        if (data.size() % 2 == 0){
            auto [l, r] = random_split(data);
            data = r;
            inserted_data.insert(inserted_data.end(), l.begin(), l.end());
            insert(root, mmap, l, allocator);
            // std::cout << data.size() << std::endl;
        } else{
            auto [l, r]  = random_split(inserted_data);
            inserted_data = r;
            del(root, mmap, l, allocator);
        }

        integrity_check(root, mmap, allocator);
    }

    std::cout << "passed" << std::endl;
}