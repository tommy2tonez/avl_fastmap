#ifndef __AVL_FASTMAP_CONTAINER_H___
#define __AVL_FASTMAP_CONTAINER_H___

#include <stdint.h>
#include <vector>
#include <memory>
#include <algorithm>
#include <numeric>
#include <functional>
#include "serialization.h"
#include <string>
#include <random>
#include <iostream>
#include <optional>
#include <array>

namespace dg::avl_fastmap::types{

    using traversal_order_type      = uint8_t;
    using buffer_len_type           = uint32_t;
    using buffer_view               = std::pair<char *, buffer_len_type>;
    using immutable_buffer_view     = std::pair<const char *, buffer_len_type>; 
    using key_type                  = uint64_t;
    using height_type               = uint8_t;
    using balance_idx_type          = int8_t;
    using balance_indicator_type    = uint8_t;
    using mapped_type               = buffer_view;
    using const_mapped_type         = immutable_buffer_view;
} 

namespace dg::avl_fastmap::constants{

    using namespace avl_fastmap::types;

    static inline constexpr size_t MINIMUM_KEY    = std::numeric_limits<key_type>::min();
    static inline constexpr size_t MAXIMUM_KEY    = std::numeric_limits<key_type>::max();
    static inline constexpr size_t MAXIMUM_DEPTH  = 64;

    enum traversal_order_options: traversal_order_type{
        preorder,
        inorder,
        postorder
    };
}

namespace dg::avl_fastmap::model{

    using namespace avl_fastmap::types;

    struct Node{
        Node * l;
        Node * r;
        key_type k;
        height_type h;
    };
}

namespace dg::avl_fastmap::memory{

    struct Allocatable{
        virtual ~Allocatable() noexcept{}
        virtual char * malloc(size_t) = 0;
        virtual void free(void *) noexcept = 0; 
    };
}

//---
namespace dg::avl_fastmap::basic_operation{

    using namespace avl_fastmap::types; 

    enum balancing_indicator_options: balance_indicator_type{
        none    = 0,
        l       = 1,
        lr      = 2,
        r       = 3,
        rl      = 4
    };

    auto get_nullable_height_at(model::Node * root) noexcept -> height_type{

        return !static_cast<bool>(root) ? 0u: root->h;
    }
    
    auto get_balance_idx_at(model::Node * root) noexcept -> balance_idx_type{

        return static_cast<balance_idx_type>(get_nullable_height_at(root->r)) - get_nullable_height_at(root->l);
    }
    
    auto get_balance_indicator_at(model::Node * root) noexcept -> balance_indicator_type{

        auto balance_idx  = get_balance_idx_at(root); 

        if (balance_idx >= -1 && balance_idx <= 1){
            return none;
        }
        
        if (balance_idx > 0){
            if (get_balance_idx_at(root->r) < 0){
                return rl;
            } else{
                return r;
            }
        } else{
            if (get_balance_idx_at(root->l) > 0){
                return lr; 
            } else{
                return l;
            }
        }
    }

    auto to_max_right(model::Node * root) noexcept -> model::Node *{
        
        return static_cast<bool>(root->r) ? to_max_right(root->r): root;
    }

    auto to_max_left(model::Node * root) noexcept -> model::Node *{

        return static_cast<bool>(root->l) ? to_max_left(root->l): root;
    }

    void update_height_at(model::Node * root) noexcept{

        root->h = std::max(get_nullable_height_at(root->l), get_nullable_height_at(root->r)) + 1;
    }

    auto rotate_l_at(model::Node * root) noexcept -> model::Node *{

        model::Node * new_root  = root->l;
        model::Node * r         = root;
        model::Node * rl        = new_root->r;

        r->l                    = rl;
        new_root->r             = r;

        update_height_at(r);
        update_height_at(new_root);

        return new_root;
    }

    auto rotate_r_at(model::Node * root) noexcept -> model::Node *{

        model::Node * new_root  = root->r;
        model::Node * l         = root;
        model::Node * lr        = new_root->l; 

        l->r                    = lr;
        new_root->l             = l;

        update_height_at(l);
        update_height_at(new_root);

        return new_root;
    }

    auto rotate_lr_at(model::Node * root) noexcept -> model::Node *{

        root->l = rotate_r_at(root->l);
        return rotate_l_at(root);
    } 

    auto rotate_rl_at(model::Node * root) noexcept -> model::Node *{

        root->r = rotate_l_at(root->r);
        return rotate_r_at(root);
    }

    auto balance_at(model::Node * root) noexcept -> model::Node *{

        auto action  = get_balance_indicator_at(root);

        switch (action){
            case none:
                return root;
            case l:
                return rotate_l_at(root);
            case r:
                return rotate_r_at(root);
            case rl:
                return rotate_rl_at(root);
            case lr:
                return rotate_lr_at(root);            
            default:
                std::abort();
                return {};
        }           
    }

    //optimizable
    auto recursive_balance_at(model::Node * root) noexcept -> model::Node *{

        while (true){

            auto prev   = root; 
            root        = balance_at(root);

            if (prev == root){
                return root;
            }
            if (root->l){
                root->l = recursive_balance_at(root->l); //semantics - recursive_balance assume non null inp (same as other)
            }
            if (root->r){
                root->r = recursive_balance_at(root->r); //semantics - recursive_balance assume non null inp - 
            }            
        }
    }
}

namespace dg::avl_fastmap::utility{

    using namespace avl_fastmap::types;

    template <class Executable>
    auto get_backout_executor(Executable executor) noexcept{

        static_assert(noexcept(executor()));

        static int guard    = 0u;
        auto destructor     = [=](int *) noexcept {executor();};
        
        return std::unique_ptr<int, decltype(destructor)>(&guard, destructor);
    }

    auto make_rm_tokens(const std::vector<key_type>& int_key_ids) -> std::unique_ptr<std::pair<key_type, bool>[]>{

        auto rs             = std::make_unique<std::pair<key_type, bool>[]>(int_key_ids.size());
        auto transformer    = [](key_type id){return std::make_pair(id, true);};
        std::transform(int_key_ids.begin(), int_key_ids.end(), rs.get(), transformer);

        return rs;
    } 
     
    template <class Functor, class ...Args>
    auto bind_back(Functor functor, Args&& ...args) noexcept{

        class NoRet{}; 

        auto tup = std::forward_as_tuple(std::forward<Args>(args)...); 

        auto rs  = [=]<class ...AArgs>(AArgs&& ...aargs){
            auto rrs = [&]<size_t ...IDX>(const std::index_sequence<IDX...>){
                using ret_type   = decltype(functor(std::forward<AArgs>(aargs)..., std::get<IDX>(tup)...));
                if constexpr(std::is_same_v<ret_type, void>){
                    functor(std::forward<AArgs>(aargs)..., std::get<IDX>(tup)...);
                    return NoRet{};
                } else{
                    return functor(std::forward<AArgs>(aargs)..., std::get<IDX>(tup)...);
                }
            }(std::make_index_sequence<sizeof...(Args)>());

            if constexpr(!std::is_same_v<decltype(rrs), NoRet>){
                return rrs;
            }
        };

        return rs;
    }
}

namespace dg::avl_fastmap::crud{

    using namespace avl_fastmap::types;

    auto heapify(model::Node ** first, model::Node ** last) noexcept -> model::Node *{

        auto sz = std::distance(first, last); 

        if (sz < 1){
            return {};
        }

        auto mid    = first + (sz >> 1);
        auto root   = *mid;
        root->l     = heapify(first, mid);
        root->r     = heapify(std::next(mid), last);
        basic_operation::update_height_at(root);

        return root;
    } 

    auto insert(model::Node * root, model::Node ** first, model::Node ** last) noexcept -> model::Node *{

        if (!root){
            return heapify(first, last);
        }

        if (std::distance(first, last) < 1){
            return root;
        }

        auto less   = [](model::Node * lhs, model::Node * rhs) noexcept{return lhs->k < rhs->k;};
        auto mid    = std::lower_bound(first, last, root, less);
        root->l     = insert(root->l, first, mid);
        root->r     = insert(root->r, mid, last);
        basic_operation::update_height_at(root);
        
        return basic_operation::recursive_balance_at(root);
    } 

    auto replace_insert(model::Node * root, model::Node ** first, model::Node ** last, model::Node **& del_nodes) noexcept -> model::Node *{

        if (!root){
            return heapify(first, last);
        }

        if (std::distance(first, last) < 1){
            return root;
        }

        auto less   = [](model::Node * lhs, model::Node * rhs) noexcept{return lhs->k < rhs->k;};
        auto mid    = std::lower_bound(first, last, root, less);
        
        if (mid == last || (*mid)->k != root->k){
            root->l         = replace_insert(root->l, first, mid, del_nodes);
            root->r         = replace_insert(root->r, mid, last, del_nodes);
        } else{
            *(del_nodes++)  = root;
            (*mid)->l       = replace_insert(root->l, first, mid, del_nodes);
            (*mid)->r       = replace_insert(root->r, std::next(mid), last, del_nodes);
            root            = *mid;
        }

        basic_operation::update_height_at(root);
        return basic_operation::recursive_balance_at(root);
    } 

    auto del(model::Node * root, 
             key_type removing_key, 
             bool is_initial,
             model::Node *& removed_node) noexcept -> model::Node *{

        if (!root){
            return {}; 
        }

        if (removing_key > root->k){
            root->r = del(root->r, removing_key, is_initial, removed_node);
            basic_operation::update_height_at(root);
            return basic_operation::balance_at(root);
        }

        if (removing_key < root->k){
            root->l = del(root->l, removing_key, is_initial, removed_node);
            basic_operation::update_height_at(root);
            return basic_operation::balance_at(root);
        }

        if (is_initial){
            removed_node = root;
        }

        if (!static_cast<bool>(root->l) && !static_cast<bool>(root->r)){
            return {};
        }

        model::Node * candidate{};

        if (root->l){   
            candidate       = basic_operation::to_max_right(root->l);
            candidate->l    = del(root->l, candidate->k, false, removed_node);
            candidate->r    = root->r;
        } else{
            candidate       = basic_operation::to_max_left(root->r);
            candidate->r    = del(root->r, candidate->k, false, removed_node);
            candidate->l    = root->l;
        }

        basic_operation::update_height_at(candidate);
        return basic_operation::balance_at(candidate);
    }

    auto del(model::Node * root, 
             std::pair<key_type, bool> * first, 
             std::pair<key_type, bool> * last,
             model::Node **& removed_nodes) noexcept -> model::Node *{

        if (!static_cast<bool>(root) || std::distance(first, last) < 1){
            return root;
        }

        auto key    = std::pair<key_type, bool>{root->k, false};
        auto less   = [](const auto& lhs, const auto& rhs) noexcept{return lhs.first < rhs.first;};
        auto mid    = std::lower_bound(first, last, key, less);
        auto tmp    = std::add_pointer_t<model::Node>{};

        if (mid == last || mid->first != root->k){
            root->l = del(root->l, first, mid, removed_nodes);
            root->r = del(root->r, mid, last, removed_nodes);
            basic_operation::update_height_at(root);
            return basic_operation::recursive_balance_at(root);
        }

        if (mid->second){
            *(removed_nodes++) = root;
        }

        if (!static_cast<bool>(root->l) && !static_cast<bool>(root->r)){
            return {};
        } 

        if (root->l){
            auto cand               = basic_operation::to_max_right(root->l);
            auto is_optimizable     = std::distance(first, mid) > 0 && (std::prev(mid)->first != cand->k);

            if (is_optimizable){
                *mid    = {cand->k, false};
                cand->l = del(root->l, first, std::next(mid), removed_nodes);
                cand->r = del(root->r, std::next(mid), last, removed_nodes);
                basic_operation::update_height_at(cand);
                return basic_operation::recursive_balance_at(cand);
            }
        } else{
            auto cand               = basic_operation::to_max_left(root->r);
            auto is_optimizable     = std::distance(mid, last) > 1 && (std::next(mid)->first != cand->k);

            if (is_optimizable){
                *mid    = {cand->k, false};
                cand->r = del(root->r, mid, last, removed_nodes);
                cand->l = del(root->l, first, mid, removed_nodes);
                basic_operation::update_height_at(cand);
                return basic_operation::recursive_balance_at(cand);
            }
        }

        root->l = del(root->l, first, mid, removed_nodes);
        root->r = del(root->r, std::next(mid), last, removed_nodes);
        basic_operation::update_height_at(root);
        return del(basic_operation::recursive_balance_at(root), mid->first, false, tmp);
    }
    
    void nullable_find(model::Node * root, 
                       const key_type * first,
                       const key_type * last,
                       model::Node **& vals) noexcept{

        if (std::distance(first, last) < 1){
            return;
        }
                
        if (!root){
            vals = std::transform(first, last, vals, [](...) noexcept{return nullptr;});
            return;
        }

        auto mid = std::lower_bound(first, last, root->k);

        if (mid != last && *mid == root->k){
            nullable_find(root->l, first, mid, vals);
            *(vals++) = root;
            nullable_find(root->r, std::next(mid), last, vals);
            return;
        } 

        nullable_find(root->l, first, mid, vals);
        nullable_find(root->r, mid, last, vals);
    }

    void find(model::Node * root, 
              const key_type *& sorted_keys, 
              model::Node **& vals,
              key_type l_bound,
              key_type r_bound) noexcept{

        if (!root){
            return;
        }
        
        if (*sorted_keys > l_bound && *sorted_keys < root->k){
            find(root->l, sorted_keys, vals, l_bound, root->k);
        }

        auto is_hit     = *sorted_keys ^ root->k;
        *vals           = root; //
        sorted_keys     += (is_hit == 0);
        vals            += (is_hit == 0);

        if (*sorted_keys > root->k && *sorted_keys < r_bound){
            find(root->r, sorted_keys, vals, root->k, r_bound);
        }
    }

    template <class Visitor>
    void post_order_traversal(model::Node * root, Visitor&& visitor) noexcept(noexcept(visitor(root))){

        if (!root){
            return;
        }

        post_order_traversal(root->l, visitor);
        post_order_traversal(root->r, visitor);
        visitor(root);
    }

    template <class Visitor>
    void in_order_traversal(model::Node * root, Visitor&& visitor) noexcept(noexcept(visitor(root))){
        
        if (!root){
            return;
        }

        in_order_traversal(root->l, visitor);
        visitor(root);
        in_order_traversal(root->r, visitor);
    }

    template <class Visitor>
    void pre_order_traversal(model::Node * root, Visitor&& visitor) noexcept(noexcept(visitor(root))){

        if (!root){
            return;
        }

        visitor(root);
        pre_order_traversal(root->l, visitor);
        pre_order_traversal(root->r, visitor);
    }
}

namespace dg::avl_fastmap::buffer_encoding{

    using namespace avl_fastmap::types; 

    constexpr auto lo_header_threshold() -> size_t{
        
        return static_cast<size_t>(std::numeric_limits<uint8_t>::max() >> 1) + 1;
    }

    constexpr auto header_size(buffer_len_type len) -> size_t{

        if (len < lo_header_threshold()){
            return sizeof(uint8_t);
        }

        return sizeof(uint8_t) + sizeof(buffer_len_type);
    } 

    auto encode_header(buffer_len_type len, char * dst) noexcept -> char *{

        if (len < lo_header_threshold()){
            uint8_t encoded = (static_cast<uint8_t>(len) << 1) | 1;
            return dg::compact_serializer::core::serialize(encoded, dst);
        }

        uint8_t encoded = 0;
        dst = dg::compact_serializer::core::serialize(encoded, dst);
        dst = dg::compact_serializer::core::serialize(len, dst); 

        return dst;
    } 

    auto decode_header(const char * src, buffer_len_type& len) noexcept -> const char *{

        uint8_t tape    = {};
        src             = dg::compact_serializer::core::deserialize(src, tape); 

        if (tape == 0u){
            return dg::compact_serializer::core::deserialize(src, len);
        }

        len = tape >> 1;
        return src;
    } 

    constexpr auto size(immutable_buffer_view buf) -> size_t{

        return header_size(buf.second) + buf.second;
    } 

    auto encode(immutable_buffer_view src, char * dst) noexcept -> char *{

        dst = encode_header(src.second, dst);
        std::memcpy(dst, src.first, src.second);
        return dst + src.second;
    }

    auto decode(const char * src, immutable_buffer_view& rs) noexcept -> const char *{

        buffer_len_type len = {};
        src = decode_header(src, len);
        rs = {src, len};

        return src + len;
    }

    auto decode(char * src, buffer_view& rs) noexcept -> char *{

        buffer_len_type len     = {};
        const char * casted     = src;
        const char * post       = decode_header(casted, len);
        rs  = {src + std::distance(casted, post), len};
        
        return rs.first + rs.second; 
    }
}

namespace dg::avl_fastmap::node_controller{

    using namespace avl_fastmap::types; 
    
    static_assert(std::is_trivial_v<model::Node>);

    auto make(key_type k, const_mapped_type v, memory::Allocatable& allocator) -> model::Node *{

        size_t sz           = sizeof(model::Node) + buffer_encoding::size(v);
        char * mem          = allocator.malloc(sz);
        model::Node * rs    = new (mem) model::Node{nullptr, nullptr, k, 1u};
        char * v_addr       = mem + sizeof(model::Node);  
        buffer_encoding::encode(v, v_addr);

        return rs;
    }

    auto extract_val(model::Node * node) noexcept -> mapped_type{

        char * v_addr       = reinterpret_cast<char *>(node) + sizeof(model::Node); 
        mapped_type mapped  = {};
        buffer_encoding::decode(v_addr, mapped);

        return mapped;
    }

    auto nullable_extract_val(model::Node * node) noexcept -> std::optional<mapped_type>{

        if (!node){
            return std::nullopt;
        }

        return extract_val(node);
    } 

    void del(model::Node * node, memory::Allocatable& allocator) noexcept{

        allocator.free(static_cast<void *>(node));
    }

    template <traversal_order_type allocation_order>
    auto make(const std::vector<std::pair<key_type, const_mapped_type>>& kvs, memory::Allocatable& allocator, const std::integral_constant<traversal_order_type, allocation_order>) -> std::unique_ptr<std::add_pointer_t<model::Node>[]>{

        auto sz             = size_t{kvs.size()};
        auto nodes          = std::make_unique<std::add_pointer_t<model::Node>[]>(sz);
        auto backout_task   = [&]() noexcept{std::for_each(nodes.get(), nodes.get() + sz, utility::bind_back(del, allocator));};
        auto backout_plan   = utility::get_backout_executor(backout_task);
        
        std::fill(nodes.get(), nodes.get() + sz, nullptr);

        auto lmaker = [&]<class Maker>(Maker& maker, size_t first, size_t last) -> model::Node *{
            if (last == first){
                return {};
            }

            auto l          = std::add_pointer_t<model::Node>{};
            auto r          = std::add_pointer_t<model::Node>{};

            size_t mid      = first + ((last - first) >> 1);

            if constexpr(allocation_order == constants::preorder){
                nodes[mid]  = make(kvs[mid].first, kvs[mid].second, allocator);
            }
            l   = maker(maker, first, mid);
            if constexpr(allocation_order == constants::inorder){
                nodes[mid]  = make(kvs[mid].first, kvs[mid].second, allocator);
            }
            r   = maker(maker, mid + 1, last);
            if constexpr(allocation_order == constants::postorder){
                nodes[mid]  = make(kvs[mid].first, kvs[mid].second, allocator);
            }

            nodes[mid]->l = l;
            nodes[mid]->r = r;

            return nodes[mid];
        };

        lmaker(lmaker, 0u, sz);
        backout_plan.release();

        return nodes;
    }
}

namespace dg::avl_fastmap::iterator_base{

    using backtrack_array = std::pair<std::array<model::Node *, constants::MAXIMUM_DEPTH>, size_t>; 

    auto size(backtrack_array& arr) noexcept{

        return arr.second;
    }

    void push_back(backtrack_array& arr, model::Node * node) noexcept{

        arr.first[arr.second++] = node;
    }

    void pop_back(backtrack_array& arr) noexcept{
    
        --arr.second;
    }

    auto back(backtrack_array& arr) noexcept -> model::Node *{

        return arr.first[arr.second - 1];
    } 

    auto equal(const backtrack_array& lhs, const backtrack_array& rhs) noexcept -> bool{

        if (lhs.second != rhs.second){
            return false;
        }

        return std::memcmp(lhs.first.data(), rhs.first.data(), lhs.second * sizeof(model::Node *)) == 0;
    }
}

namespace dg::avl_fastmap::inorder_iterator{
    
    using namespace avl_fastmap::types;
    using namespace avl_fastmap::iterator_base;

    class iterator{

        private:

            backtrack_array trace;

        public:

            iterator(backtrack_array trace) noexcept: trace(trace){}

            iterator& operator ++() noexcept{

                increment();
                return *this;
            }

            bool operator != (const iterator& other) noexcept{
                
                return !equal(this->trace, other.trace);
            }

            std::pair<key_type, mapped_type> operator *() noexcept{
                
                return {back(this->trace)->k, node_controller::extract_val(back(this->trace))};
            }

        private:

            void increment() noexcept{ 

                if (size(trace) == 0u){
                    return;
                }

                if (back(trace)->r){
                    push_back(trace, back(trace)->r);
                    while (back(trace)->l){
                        push_back(trace, back(trace)->l);
                    }
                    return;
                }

                while (size(trace) != 1u){

                    auto cur = back(trace);
                    pop_back(trace);
                    auto par = back(trace);

                    if (par->l == cur){
                        return;
                    }
                }

                pop_back(trace);
            }
    };

    auto end() noexcept -> iterator{

        return iterator{{}};
    }

    auto begin(model::Node * root) noexcept -> iterator{

        if (!root){
            return end();
        }

        auto trace = backtrack_array{};
        push_back(trace, root);

        while (back(trace)->l){
            push_back(trace, back(trace)->l);
        }
        
        return iterator(trace);
    }
} 

namespace dg::avl_fastmap{

    //minimum viable product - this interface suffices for most usecases 
    using namespace avl_fastmap::types; 
    using namespace avl_fastmap::constants;

    auto make() -> model::Node *{

        return {};
    }
    
    auto deallocate(model::Node * root, memory::Allocatable& allocator) noexcept -> model::Node *{

        crud::post_order_traversal(root, utility::bind_back(node_controller::del, allocator));
        return {};
    } 

    auto size(model::Node * root) noexcept{

        size_t count{};
        crud::post_order_traversal(root, [&](...) noexcept{++count;});
        return count;
    }

    //non-existing-key
    auto sorted_insert(model::Node * root, 
                       const std::vector<std::pair<key_type, const_mapped_type>>& kvs, 
                       memory::Allocatable& allocator, 
                       traversal_order_type allocation_order = preorder) -> model::Node *{
        
        auto nodes  = std::unique_ptr<std::add_pointer_t<model::Node>[]>{}; 

        switch (allocation_order){
            
            case constants::preorder:
                nodes   = node_controller::make(kvs, allocator, std::integral_constant<traversal_order_type, constants::preorder>{});
                break;
            
            case constants::inorder:
                nodes   = node_controller::make(kvs, allocator, std::integral_constant<traversal_order_type, constants::inorder>{});
                break;

            case constants::postorder:
                nodes   = node_controller::make(kvs, allocator, std::integral_constant<traversal_order_type, constants::postorder>{});
                break;

            default:
                std::abort();
                break; 
        };

        return crud::insert(root, nodes.get(), nodes.get() + kvs.size());
    }
    
    auto sorted_replace_insert(model::Node * root, 
                               const std::vector<std::pair<key_type, const_mapped_type>>& kvs, 
                               memory::Allocatable& allocator, 
                               traversal_order_type allocation_order = preorder) -> model::Node *{
        
        auto nodes          = std::unique_ptr<std::add_pointer_t<model::Node>[]>{}; 
        auto rm_nodes       = std::make_unique<std::add_pointer_t<model::Node>[]>(kvs.size());
        auto rm_nodes_head  = rm_nodes.get();

        switch (allocation_order){
            
            case constants::preorder:
                nodes   = node_controller::make(kvs, allocator, std::integral_constant<traversal_order_type, constants::preorder>{});
                break;
            
            case constants::inorder:
                nodes   = node_controller::make(kvs, allocator, std::integral_constant<traversal_order_type, constants::inorder>{});
                break;

            case constants::postorder:
                nodes   = node_controller::make(kvs, allocator, std::integral_constant<traversal_order_type, constants::postorder>{});
                break;

            default:
                std::abort();
                break; 
        };

        root = crud::replace_insert(root, nodes.get(), nodes.get() + kvs.size(), rm_nodes_head);
        std::for_each(rm_nodes.get(), rm_nodes_head, utility::bind_back(node_controller::del, allocator));

        return root;
    }

    auto sorted_del(model::Node * root, 
                    const std::vector<key_type>& keys,
                    memory::Allocatable& allocator) -> model::Node *{
        

        auto sz             = keys.size();
        auto rm_tokens      = utility::make_rm_tokens(keys);
        auto rm_nodes       = std::make_unique<std::add_pointer_t<model::Node>[]>(sz); //
        auto rm_nodes_ptr   = rm_nodes.get(); 
        root                = crud::del(root, rm_tokens.get(), rm_tokens.get() + sz, rm_nodes_ptr);
        std::for_each(rm_nodes.get(), rm_nodes.get() + sz, utility::bind_back(node_controller::del, allocator));

        return root;
    }

    auto del(model::Node * root, 
             key_type key,
             memory::Allocatable& allocator) noexcept -> model::Node *{
        
        auto rm_node    = std::add_pointer_t<model::Node>{};
        root            = crud::del(root, key, true, rm_node);
        node_controller::del(rm_node, allocator);
        
        return root;
    }

    //existing keys within (MINIMUM_KEY, MAXIMUM_KEY)
    void sorted_find(model::Node * root, 
                     const std::vector<key_type>& keys,
                     std::vector<mapped_type>& vals){
        
        auto sz         = keys.size() + 1;
        auto nodes      = std::make_unique<std::add_pointer_t<model::Node>[]>(sz);
        auto nodes_ptr  = nodes.get();

        {
            auto kkeys      = std::make_unique<key_type[]>(sz);
            auto kkeys_ptr  = static_cast<const key_type *>(kkeys.get());
            std::memcpy(kkeys.get(), keys.data(), static_cast<size_t>(sizeof(key_type)) * keys.size());
            kkeys[keys.size()] = constants::MAXIMUM_KEY; 
            crud::find(root, kkeys_ptr, nodes_ptr, constants::MINIMUM_KEY, constants::MAXIMUM_KEY);
        }
        
        std::transform(nodes.get(), nodes.get() + keys.size(), std::back_inserter(vals), node_controller::extract_val);
    }

    void std_sorted_find(model::Node * root, 
                         const std::vector<key_type>& keys, 
                         std::vector<std::optional<mapped_type>>& vals){
        
        auto nodes      = std::make_unique<std::add_pointer_t<model::Node>[]>(keys.size());
        auto nodes_ptr  = nodes.get();
        crud::nullable_find(root, keys.data(), keys.data() + keys.size(), nodes_ptr);
        std::transform(nodes.get(), nodes.get() + keys.size(), std::back_inserter(vals), node_controller::nullable_extract_val);
    }

    template <class Visitor>
    auto visit(model::Node * root, Visitor visitor, traversal_order_type traversal_order = preorder) noexcept(noexcept(visitor(std::declval<key_type>(), std::declval<mapped_type>()))){

        auto liaison = [visitor](model::Node * root) noexcept(noexcept(visitor(std::declval<key_type>(), std::declval<mapped_type>()))){
            visitor(root->k, node_controller::extract_val(root));
        };

        switch (traversal_order){
            case preorder:
                crud::pre_order_traversal(root, liaison);
                break;
            case inorder:
                crud::in_order_traversal(root, liaison);
                break;
            case postorder:
                crud::post_order_traversal(root, liaison);
                break;
            default:
                std::abort();
                break;
        }
    } 

    auto begin(model::Node * root) noexcept -> inorder_iterator::iterator{

        return inorder_iterator::begin(root);
    }

    auto end() noexcept -> inorder_iterator::iterator{

        return inorder_iterator::end();
    }
}

#endif