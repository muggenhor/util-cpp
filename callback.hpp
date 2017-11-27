/*
 * Copyright (C) 2017  Giel van Schijndel
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef __INCLUDED_CALLBACK_HPP__
#define __INCLUDED_CALLBACK_HPP__

#include <boost/optional/optional.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/variant.hpp>
#include <cassert>
#include <cstddef>
#include <functional>
#include <iterator>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>

namespace util
{
  template <typename T>
  const std::shared_ptr<T>& acquire_lock(const std::shared_ptr<T>& p)
  {
    return p;
  }

  template <typename T>
  std::shared_ptr<T> acquire_lock(const std::weak_ptr<T>& p)
  {
    return p.lock();
  }

  template <typename T>
  T* acquire_lock(T* p)
  {
    return p;
  }

  template <typename T>
  auto to_address(T p) -> decltype(&*p)
  {
    return &*p;
  }

  void to_address(bool) {}

  template <typename FunctionSignature, std::size_t SmallBufferSize = sizeof(void (std::true_type::*)()) + sizeof(std::weak_ptr<void>)>
  class callback;

  namespace detail
  {
    template <typename...>
    struct void_t_helper
    {
      using type = void;
    };
    template <typename... Args>
    using void_t = typename void_t_helper<Args...>::type;

    template <typename Result, typename Ret, typename = void>
      struct __is_callable_impl : std::false_type {};

    template <typename Result, typename Ret>
      struct __is_callable_impl<Result, Ret, void_t<typename Result::type>>
      : std::true_type
    {};

    template <typename F, typename... Args>
      struct is_callable
      : __is_callable_impl<std::result_of<F(Args...)>, void>::type
    {};

    template <std::size_t... I>
    struct index_sequence {};

    template <std::size_t N, std::size_t... I> 
    struct make_index_sequence 
        : make_index_sequence<N-1, N-1, I...> 
    {};

    template <std::size_t... I> 
    struct make_index_sequence<0, I...> 
        : index_sequence<I...> 
    {};

    template <typename>
    struct is_callback_impl : std::false_type {};

    template <typename FunctionSignature, std::size_t SmallBufferSize>
    struct is_callback_impl<callback<FunctionSignature, SmallBufferSize>> : std::true_type {};

    template <typename T>
    using is_callback = is_callback_impl<typename std::decay<T>::type>;

    template <typename R>
    struct callbackret_s
    {
      using type = boost::optional<R>;
    };

    template <>
    struct callbackret_s<void>
    {
      using type = bool;
    };

    template <typename R>
    using callback_ret = typename callbackret_s<R>::type;

    template <typename R>
    struct ret_invoke_helper
    {
      template <typename F, typename... Args>
      typename std::enable_if<is_callable<F, Args...>::value && !is_callback<F>::value, callback_ret<R>>::type
      static do_invoke(F&& f, Args&&... args)
      {
        return static_cast<R>(std::forward<F>(f)(std::forward<Args>(args)...));
      }

      template <typename F, typename... Args>
      typename std::enable_if<is_callable<F, Args...>::value && is_callback<F>::value, callback_ret<R>>::type
      static do_invoke(F&& f, Args&&... args)
      {
        if (auto r = std::forward<F>(f)(std::forward<Args>(args)...))
          return r;
        return {};
      }

      template <typename O, typename F, typename... Args>
      typename std::enable_if<is_callable<F, Args...>::value, callback_ret<R>>::type
      static do_invoke(O&&, F&& f, Args&&... args)
      {
        return do_invoke(std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename O, typename F, typename... Args>
      typename std::enable_if<is_callable<F, O, Args...>::value, callback_ret<R>>::type
      static do_invoke(O&& that, F&& f, Args&&... args)
      {
        return do_invoke(std::forward<F>(f), std::forward<O>(that), std::forward<Args>(args)...);
      }

      template <typename FR, typename O, typename... Args>
      static callback_ret<R> do_invoke(O* that, FR O::* f, Args&&... args)
      {
        return static_cast<R>((that->*f)(std::forward<Args>(args)...));
      }
    };

    template <>
    struct ret_invoke_helper<void>
    {
      using R = void;

      template <typename F, typename... Args>
      typename std::enable_if<is_callable<F, Args...>::value && !is_callback<F>::value, callback_ret<R>>::type
      static do_invoke(F&& f, Args&&... args)
      {
        return (std::forward<F>(f)(std::forward<Args>(args)...), true);
      }

      template <typename F, typename... Args>
      typename std::enable_if<is_callable<F, Args...>::value && is_callback<F>::value, callback_ret<R>>::type
      static do_invoke(F&& f, Args&&... args)
      {
        return static_cast<bool>(std::forward<F>(f)(std::forward<Args>(args)...));
      }

      template <typename O, typename F, typename... Args>
      typename std::enable_if<is_callable<F, Args...>::value, callback_ret<R>>::type
      static do_invoke(O&&, F&& f, Args&&... args)
      {
        return do_invoke(std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename O, typename F, typename... Args>
      typename std::enable_if<is_callable<F, O, Args...>::value, callback_ret<R>>::type
      static do_invoke(O&& that, F&& f, Args&&... args)
      {
        return do_invoke(std::forward<F>(f), std::forward<O>(that), std::forward<Args>(args)...);
      }

      template <typename FR, typename O, typename... Args>
      static callback_ret<R> do_invoke(O* that, FR O::* f, Args&&... args)
      {
        return ((that->*f)(std::forward<Args>(args)...), true);
      }
    };

    template <typename... Args>
    struct callback_helper
    {
      template <typename R, typename RawAddress, typename O, typename F>
      typename std::enable_if<!std::is_void<RawAddress>::value, callback_ret<R>>::type
      static do_invoke_dereference(O&& that, F&& f, Args... args)
      {
        using ::util::to_address;
        return ret_invoke_helper<R>::do_invoke(to_address(std::forward<O>(that)), std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename R, typename RawAddress, typename O, typename F>
      typename std::enable_if<std::is_void<RawAddress>::value, callback_ret<R>>::type
      static do_invoke_dereference(O&&, F&& f, Args... args)
      {
        return ret_invoke_helper<R>::do_invoke(std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename R, typename O, typename F, std::size_t... I>
      static callback_ret<R> do_invoke_expand(O&& that, F&& f, std::tuple<Args...>&& args, index_sequence<I...>)
      {
        using ::util::to_address;
        using raw_address_t = decltype(to_address(std::forward<O>(that)));
        return do_invoke_dereference<R, raw_address_t>(std::forward<O>(that), std::forward<F>(f), std::get<I>(std::move(args))...);
      }

      template <typename R, typename O, typename F>
      static callback_ret<R> do_invoke(O&& that, F&& f, std::tuple<Args...>&& args)
      {
        return do_invoke_expand<R>(std::forward<O>(that), std::forward<F>(f), std::move(args), make_index_sequence<sizeof...(Args)>{});
      }
    };

    struct always_valid_ptr {};
    inline constexpr bool acquire_lock(const always_valid_ptr&)
    {
      return true;
    }

    template <typename... Args>
    struct callback_tag_invoke
    {
      explicit constexpr callback_tag_invoke(Args... args)
          noexcept(noexcept(std::tuple<Args...>(std::forward<Args>(args)...)))
        : args(std::forward<Args>(args)...)
      {
      }

      std::tuple<Args...> args;
    };

    struct callback_tag_is_valid
    {
      explicit constexpr callback_tag_is_valid(bool& r) noexcept : ret(r) {}
      bool& ret;
    };

    struct callback_tag_determine_used_storage_size
    {
      constexpr callback_tag_determine_used_storage_size(size_t& used_storage_size) noexcept
        : used_storage_size(used_storage_size)
      {}

      size_t& used_storage_size;
    };

    struct callback_tag_clone
    {
      explicit constexpr callback_tag_clone(void* dst) noexcept : dst(dst) {}
      void* const dst;
    };

    struct callback_tag_move
    {
      explicit constexpr callback_tag_move(void* src, void* dst) noexcept : src(std::move(src)), dst(dst) {}
      void* const src;
      void* const dst;
    };

    struct callback_tag_move_resize
    {
      explicit constexpr callback_tag_move_resize(void* src, void* dst, size_t size, size_t align, void (*&invoker)()) noexcept
        : src(std::move(src)), dst(dst), size(size), align(align), invoker(invoker) {}
      void* const src;
      void* const dst;
      size_t const size;
      size_t const align;
      void (*&invoker)();
    };

    struct callback_tag_delete {};

    template <typename... Args>
    using callback_method = boost::variant<
        callback_tag_invoke<Args...>
      , callback_tag_is_valid
      , callback_tag_determine_used_storage_size
      , callback_tag_move
      , callback_tag_move_resize
      , callback_tag_clone
      , callback_tag_delete
      >;

    template <typename R, typename... Args>
    using callback_method_invoker = callback_ret<R> (*)(const void* that, callback_method<Args...>&& call);

    template <typename T>
    struct non_ebo_wrapper
    {
      constexpr non_ebo_wrapper(const T& v) : v(v) {}
      constexpr non_ebo_wrapper(T&& v) : v(std::move(v)) {}

      operator T&()
      {
        return v;
      }

      constexpr operator const T&() const
      {
        return v;
      }

      T v;
    };

    template <typename T>
    using ebo_t = typename std::conditional<std::is_empty<T>::value, T, non_ebo_wrapper<T>>::type;

    template <typename T>
    struct pointer_wrapper
    {
    public:
      constexpr pointer_wrapper(T p) : pointer(p) {}

      friend constexpr T acquire_lock(const pointer_wrapper& p)
      {
        using ::util::acquire_lock;
        return acquire_lock(p.pointer);
      }

    private:
      T pointer;
    };

    template <typename T>
    struct wrap_pointer
    {
      using type = T;
    };

    template <typename T>
    struct wrap_pointer<T*>
    {
      using type = pointer_wrapper<T*>;
    };

    template <typename T>
    using wrap_pointer_t = typename wrap_pointer<T>::type;

    template <typename T>
    typename std::enable_if<std::is_constructible<bool, T>::value, bool>::type
    constexpr convert_to_bool_or_true(const T& o)
    {
      return static_cast<bool>(o);
    }

    template <typename T>
    typename std::enable_if<!std::is_constructible<bool, T>::value, bool>::type
    constexpr convert_to_bool_or_true(const T&)
    {
      return true;
    }

    template <typename LockablePtr, typename F, typename R, typename... Args>
    class callback_impl final : // inherit for empty-base optimisation
                                 private wrap_pointer_t<LockablePtr>
                               , private ebo_t<F>
    {
    private:
      using pointer_base = wrap_pointer_t<LockablePtr>;
      using functor_base = ebo_t<F>;

      callback_impl(LockablePtr p, F f)
        : pointer_base(std::forward<LockablePtr>(p))
        , functor_base(std::forward<F>(f))
      {}

      template <bool stored_internally>
      class invoke_visitor
      {
      private:
        friend class callback_impl;
        invoke_visitor(const callback_impl& that) : that(that) {}
        const callback_impl& that;

      public:
        using result_type = callback_ret<R>;

        callback_ret<R> operator()(detail::callback_tag_invoke<Args...>& op) const
        {
          using ::util::acquire_lock;

          // Casting away constness because 'mutable' isn't an option with the empty base optimization
          F& f = const_cast<callback_impl&>(that);

          if (auto i = acquire_lock(static_cast<const pointer_base&>(that)))
          {
            return callback_helper<Args...>::template do_invoke<R>(std::forward<decltype(i)>(i), f, std::move(op.args));
          }
          else
          {
            return {};
          }
        }

        callback_ret<R> operator()(const callback_tag_is_valid& op) const noexcept
        {
          using ::util::acquire_lock;
          const F& f = that;
          op.ret = convert_to_bool_or_true(f) && static_cast<bool>(acquire_lock(static_cast<const pointer_base&>(that)));
          return {};
        }

        callback_ret<R> operator()(const callback_tag_determine_used_storage_size& op) const noexcept
        {
          op.used_storage_size = stored_internally
            ? (std::is_empty<callback_impl>::value ? 0 : sizeof(callback_impl))
            : sizeof(callback_impl*)
            ;
          return {};
        }

        callback_ret<R> operator()(const callback_tag_move& op) const noexcept
        {
          assert(op.src != op.dst && "move constructing to the same address is illegal!");

          if (stored_internally)
          {
            auto* const thatp = static_cast<callback_impl*>(op.src);
            assert(thatp == &that && "move constructor doesn't apply to this type!");

            ::new (op.dst) callback_impl{std::move(*thatp)};
            thatp->~callback_impl();
          }
          else
          {
            auto*& thatp = *static_cast<callback_impl**>(op.src);
            assert(thatp == &that && "move constructor doesn't apply to this type!");

            *static_cast<callback_impl**>(op.dst) = thatp;
            thatp = nullptr;
          }
          return {};
        }

        callback_ret<R> operator()(const callback_tag_move_resize& op) const
        {
          assert(op.src != op.dst && "move constructing to the same address is illegal!");

          const bool dst_stored_internally = true
            && (sizeof (callback_impl) <= op.size || std::is_empty<callback_impl>::value)
            && (op.align       % alignof(callback_impl)) == 0
            // external storage allows us to just move a pointer: that's guaranteed not to throw
            && std::is_nothrow_move_constructible<callback_impl>::value
            ;

          op.invoker = reinterpret_cast<void (*)()>(dst_stored_internally
              ? invoke_method<true> : invoke_method<false>);

          if (stored_internally == dst_stored_internally)
          {
            return (*this)(callback_tag_move{op.src, op.dst});
          }

          if (stored_internally)
          {
            assert(!dst_stored_internally);

            auto* const thatp = static_cast<callback_impl*>(op.src);
            assert(thatp == &that && "move constructor doesn't apply to this type!");

            if (sizeof(callback_impl*) > op.size)
              throw std::length_error("storage area not large enough to store a pointer for external storage!");
            *static_cast<callback_impl**>(op.dst) = new callback_impl{std::move(*thatp)};
            that.~callback_impl();
          }
          else
          {
            assert(dst_stored_internally);

            auto*& thatp = *static_cast<callback_impl**>(op.src);
            assert(thatp == &that && "move constructor doesn't apply to this type!");

            ::new (op.dst) callback_impl{std::move(*thatp)};
            thatp = nullptr;
            delete &that;
          }
          return {};
        }

        callback_ret<R> operator()(const callback_tag_clone& op) const
        {
          if (stored_internally)
            ::new (op.dst) callback_impl{that};
          else
            *static_cast<callback_impl**>(op.dst) = new callback_impl{that};
          return {};
        }

        callback_ret<R> operator()(const callback_tag_delete&) const
        {
          if (stored_internally)
            that.~callback_impl();
          else
            delete &that;
          return {};
        }
      };

      template <bool stored_internally>
      static callback_ret<R> invoke_method(const void* s, callback_method<Args...>&& call)
      {
        auto* const that = stored_internally
          ? static_cast<const callback_impl*>(s)
          : *static_cast<const callback_impl* const *>(s)
          ;

        return boost::apply_visitor(invoke_visitor<stored_internally>{*that}, call);
      }

      template <typename R2, typename... Args2, typename Storage2, typename LockablePtr2, typename F2>
      friend callback_method_invoker<R2, Args2...> construct_callback_impl(Storage2& s, LockablePtr2 p, F2 f);
    };

    template <typename R, typename... Args, typename Storage, typename LockablePtr, typename F>
    callback_method_invoker<R, Args...> construct_callback_impl(Storage& s, LockablePtr p, F f)
    {
      void* const dst = &s;

      using impl_t = callback_impl<typename std::decay<LockablePtr>::type, typename std::decay<F>::type, R, Args...>;

      constexpr const bool stored_internally = true
        && (sizeof (impl_t) <= Storage::size || std::is_empty<impl_t>::value)
        && (Storage::align   % alignof(impl_t)) == 0
        // external storage allows us to just move a pointer: that's guaranteed not to throw
        && std::is_nothrow_move_constructible<impl_t>::value
        ;

      if (stored_internally)
      {
        ::new (dst) impl_t{std::forward<LockablePtr>(p), std::forward<F>(f)};
      }
      else
      {
        static_assert(stored_internally || sizeof(impl_t*) <= Storage::size, "storage area not large enough to store a pointer for external storage!");
        *static_cast<impl_t**>(dst) = new impl_t{std::forward<LockablePtr>(p), std::forward<F>(f)};
      }
      return impl_t::template invoke_method<stored_internally>;
    }

    template <typename R, typename... Args, typename Storage, typename LockablePtr, typename FS, std::size_t FSBS>
    callback_method_invoker<R, Args...> construct_callback_impl(Storage& s, LockablePtr p, callback<FS, FSBS>&& f, const std::size_t used_storage_size, std::integral_constant<std::size_t, 0>)
    {
      // Termination condition
      assert(used_storage_size == 0);
      return construct_callback_impl<R, Args...>(s, std::move(p), callback<FS, 0>{std::move(f)});
    }

    template <typename R, typename... Args, typename Storage, typename LockablePtr, std::size_t SBS, typename FS, std::size_t FSBS>
    callback_method_invoker<R, Args...> construct_callback_impl(Storage& s, LockablePtr p, callback<FS, FSBS>&& f, const std::size_t used_storage_size, std::integral_constant<std::size_t, SBS> current_size)
    {
      const auto needed_blocks = (used_storage_size + Storage::align - 1) / Storage::align;
      constexpr auto cur_blocks = (current_size + Storage::align - 1) / Storage::align;

      if (needed_blocks < cur_blocks)
        return construct_callback_impl<R, Args...>(s, std::move(p), std::move(f), used_storage_size, std::integral_constant<std::size_t, (cur_blocks - 1) * Storage::align>{});

      // Fall back to pointer size if it won't fit in the storage area anyway
      if (used_storage_size > current_size)
        return construct_callback_impl<R, Args...>(s, std::move(p), callback<FS, sizeof(void*)>{std::move(f)});

      // Seems we've found our size: go with it
      return construct_callback_impl<R, Args...>(s, std::move(p), callback<FS, current_size>{std::move(f)});
    }

    template <typename R, typename... Args, typename Storage, typename LockablePtr, typename FS, std::size_t FSBS>
    callback_method_invoker<R, Args...> construct_callback_impl(Storage& s, LockablePtr p, callback<FS, FSBS>&& f, const std::size_t used_storage_size)
    {
      return construct_callback_impl<R, Args...>(s, std::move(p), std::move(f), used_storage_size, std::integral_constant<std::size_t, Storage::size>{});
    }

    template <std::size_t SmallBufferSize>
    class callback_storage
    {
      private:
        typename std::aligned_storage<SmallBufferSize, alignof(void*)>::type _store;

      public:
        static constexpr const std::size_t size  = sizeof(_store);
        static constexpr const std::size_t align = alignof(decltype(_store));

                  void      * data()       noexcept { return &_store; }
        constexpr void const* data() const noexcept { return &_store; }

      protected:
                  callback_storage      & storage()       noexcept { return *this; }
        constexpr callback_storage const& storage() const noexcept { return *this; }
    };

    template <>
    class callback_storage<std::size_t(0)>
    {
      public:
        static constexpr const std::size_t size  = 0;
        static constexpr const std::size_t align = 1;

                  void      * data()       noexcept { return this; }
        constexpr void const* data() const noexcept { return this; }

      protected:
                  callback_storage      & storage()       noexcept { return *this; }
        constexpr callback_storage const& storage() const noexcept { return *this; }
    };
  }

  template <std::size_t SmallBufferSize, typename R, typename... Args>
  class callback<R(Args...), SmallBufferSize> : private detail::callback_storage<SmallBufferSize>
  {
    private:
      using storage_t = detail::callback_storage<SmallBufferSize>;
    public:
      constexpr callback() noexcept = default;
      constexpr callback(std::nullptr_t) noexcept {}

      callback(const callback& other)
        : invoker([&] {
            if (other.invoker)
              other.invoker(other.data(), detail::callback_tag_clone{this->data()});
            return other.invoker;
          }())
      {
      }

      callback(callback&& other) noexcept
        : invoker([&] {
            auto invoke = other.invoker;
            if (invoke)
            {
              invoke(other.data(), detail::callback_tag_move{other.data(), this->data()});
              other.invoker = nullptr;
            }
            return invoke;
          }())
      {
      }

      template <std::size_t FSBS
        , typename = typename std::enable_if<
           !std::is_same<callback<R(Args...), FSBS>, callback>::value // prevent nested type-erasure instead of copy construction
        >::type>
      callback(callback<R(Args...), FSBS> other)
        : invoker([&]() -> decltype(invoker) {
            if (other.invoker)
            {
              void (*new_invoker)() = nullptr;
              other.invoker(other.data(), detail::callback_tag_move_resize{
                  other.data(), this->data(), storage_t::size, storage_t::align, new_invoker});
              other.invoker = nullptr;
              assert(new_invoker != nullptr);
              return reinterpret_cast<decltype(invoker)>(new_invoker);
            }
            return nullptr;
          }())
      {
      }

      ~callback() noexcept
      {
        *this = nullptr;
      }

      template <typename F
        , typename = typename std::enable_if<
           !std::is_same<typename std::decay<F>::type, callback>::value // prevent nested type-erasure instead of copy construction
            && (std::is_convertible<typename std::result_of<F(Args...)>::type, R>::value
             || std::is_void<R>::value
         )>::type>
      callback(F f)
        : invoker(detail::construct_callback_impl<R, Args...>(this->storage(), detail::always_valid_ptr{}, std::forward<F>(f)))
      {
      }

      template <typename FR, typename... FArgs, std::size_t FSBS
        , typename = typename std::result_of<callback<FR(FArgs...), FSBS>(Args...)>::type
        , typename = typename std::enable_if<
           !std::is_same<callback<FR(FArgs...), FSBS>, callback>::value // prevent nested type-erasure instead of copy construction
            && (std::is_convertible<FR, R>::value
             || std::is_void<R>::value
         )>::type>
      explicit callback(callback<FR(FArgs...), FSBS> f)
        : invoker([&]() -> decltype(invoker) {
            if (!f.invoker)
              return nullptr;
            size_t used_storage_size = 0;
            f.invoker(f.data(), detail::callback_tag_determine_used_storage_size{used_storage_size});

            return detail::construct_callback_impl<R, Args...>(this->storage(), detail::always_valid_ptr{}, std::move(f), used_storage_size);
          }())
      {
      }

      template <typename LockablePtr, typename F
        , typename = typename std::enable_if<
            std::is_convertible<typename std::result_of<F(Args...)>::type, R>::value
         || std::is_void<R>::value
         >::type>
      callback(F f, LockablePtr p)
        : invoker(acquire_lock(p)
                ? detail::construct_callback_impl<R, Args...>(this->storage(), std::forward<LockablePtr>(p), std::forward<F>(f))
                : nullptr
                )
      {
      }

      template <typename LockablePtr, typename F>
      callback(F f, LockablePtr p
          , typename std::enable_if<
               std::is_convertible<typename std::result_of<F(typename std::pointer_traits<LockablePtr>::element_type*, Args...)>::type, R>::value
            || std::is_void<R>::value
            >::type* = nullptr)
        : invoker(acquire_lock(p)
                ? detail::construct_callback_impl<R, Args...>(this->storage(), std::forward<LockablePtr>(p), std::forward<F>(f))
                : nullptr
                )
      {
      }

      callback& operator=(callback rhs) noexcept
      {
        *this = nullptr;
        if (rhs.invoker)
        {
          rhs.invoker(rhs.data(), detail::callback_tag_move{rhs.data(), this->data()});
          invoker = rhs.invoker;
          rhs.invoker = nullptr;
        }
        return *this;
      }

      callback& operator=(std::nullptr_t) noexcept
      {
        if (invoker)
        {
          auto invoke = invoker;
          invoker = nullptr;
          invoke(this->data(), detail::callback_tag_delete{});
        }
        return *this;
      }

      explicit operator bool() const noexcept
      {
        bool is_valid = false;
        if (invoker)
          invoker(this->data(), detail::callback_tag_is_valid{is_valid});
        return is_valid;
      }

      detail::callback_ret<R> operator()(Args... args) const
      {
        if (!invoker)
          throw std::bad_function_call();
        return invoker(this->data(), detail::callback_tag_invoke<Args...>{std::forward<Args>(args)...});
      }

    private:
      detail::callback_method_invoker<R, Args...> invoker = nullptr;

      template <typename, std::size_t>
      friend class callback;
  };

  template <typename ForwardRange, typename... Args>
  void emit_all(ForwardRange& callbacks, Args... args)
  {
    using std::begin;
    using std::end;

    using iterator = decltype(begin(callbacks));
    using reference = typename std::iterator_traits<iterator>::reference;

    callbacks.erase(
        std::remove_if(begin(callbacks), end(callbacks),
          [&](reference cb) {
            return !cb(std::forward<Args>(args)...);
          })
      , end(callbacks)
      );
  }
}

#ifdef TEST
#include <vector>

struct U {};
static_assert(std::is_empty<util::detail::callback_impl<util::detail::always_valid_ptr, U, void, void*>>::value, "");
static_assert(sizeof(util::detail::callback_impl<util::detail::always_valid_ptr, void (*)(void*), void, void*>) == sizeof(void*) * 1, "");
static_assert(sizeof(util::detail::callback_impl<void*                   , void (*)(void*), void, void*>) == sizeof(void*) * 2, "");
static_assert(sizeof(util::detail::callback_impl<std::weak_ptr<void>     , void (*)(void*), void, void*>) == sizeof(void*) * 3, "");
static_assert(sizeof(util::detail::callback_impl<U*                      , void (U::*)(), void>) == sizeof(void*) * 3, "");
static_assert(sizeof(util::detail::callback_impl<std::weak_ptr<U   >     , void (U::*)(), void>) == sizeof(void*) * 4, "");

namespace
{
  int some_f(int, char) { return 0; }

  struct S
  {
    int operator()(int, char) const { return 1; }
    int f(int, char) const { return 2; }
  };

  struct Z
  {
    int operator()(int&& a, char) { ++a; return 1; }
  };
}

int main()
{
  using namespace util;

  callback<void (int, char), 0> w{S{}};
  callback<void (int, char)> x(some_f);
  callback<void (int, char)> y{x};
  callback<void (int, char), sizeof(void (*)())> z{std::move(x)};

  static_assert(sizeof(w) == sizeof(void (*)()), "minimimum type erasure size exceeds that of a function pointer");

  {
    auto s = std::make_shared<S>();
    std::vector<callback<int (int&&, char&&)>> v {
      {Z{}},
      {&S::f, std::weak_ptr<S>(s)},
      {&S::f, std::make_shared<S>()},
      {S{}},
    };

    emit_all(v, 7, 'z');
    s.reset();
    emit_all(v, 14, 'y');
  }

  w(0, 'a');
  y(1, 'b');
  z(2, 'c');

  try
  {
    assert(!x);
    x(4, 'e');
    assert(!"expected an std::bad_function_call exception!");
  }
  catch (std::bad_function_call const&)
  {
  }
}
#endif

#endif /* __INCLUDED_CALLBACK_HPP__ */
