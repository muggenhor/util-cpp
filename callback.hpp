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

  template <typename FunctionSignature>
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

    template <typename FunctionSignature>
    struct is_callback_impl<callback<FunctionSignature>> : std::true_type {};

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
      typename std::enable_if<!std::is_same<RawAddress, void>::value, callback_ret<R>>::type
      static do_invoke_dereference(O&& that, F&& f, Args... args)
      {
        using ::util::to_address;
        return ret_invoke_helper<R>::do_invoke(to_address(std::forward<O>(that)), std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename R, typename RawAddress, typename O, typename F>
      typename std::enable_if<std::is_same<RawAddress, void>::value, callback_ret<R>>::type
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

    using storage_t = std::aligned_storage<
        sizeof(void (always_valid_ptr::*)()) + sizeof(std::weak_ptr<void>)
      , alignof(std::weak_ptr<void>)
      >::type;

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

    struct callback_tag_clone
    {
      explicit constexpr callback_tag_clone(storage_t& dst) noexcept : dst(dst) {}
      storage_t& dst;
    };

    struct callback_tag_move
    {
      explicit constexpr callback_tag_move(storage_t&& src, storage_t& dst) noexcept : src(std::move(src)), dst(dst) {}
      storage_t&& src;
      storage_t& dst;
    };

    struct callback_tag_delete {};

    template <typename... Args>
    using callback_method = boost::variant<
        callback_tag_invoke<Args...>
      , callback_tag_is_valid
      , callback_tag_move
      , callback_tag_clone
      , callback_tag_delete
      >;

    template <typename R, typename... Args>
    using callback_method_invoker = callback_ret<R> (*)(const storage_t& that, callback_method<Args...>&& call);

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

    template <typename T, typename Storage>
    struct callback_stored_internally
    {
      static constexpr const bool value = true
        &&  sizeof (T)      <= sizeof(Storage)
        && (alignof(Storage) % alignof(T)) == 0
        // force external storage (tracked via ptr) if the contained type isn't noexcept movable
        && noexcept(T{std::declval<T>()})
        ;
    };

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

      public: // for boost::apply_visitor only
        using result_type = callback_ret<R>;

        callback_ret<R> operator()(detail::callback_tag_invoke<Args...>& op) const
        {
          using ::util::acquire_lock;

          // Casting away constness because 'mutable' isn't an option with the empty base optimization
          F& f = const_cast<callback_impl&>(*this);

          if (auto i = acquire_lock(static_cast<const pointer_base&>(*this)))
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
          const F& f = *this;
          op.ret = convert_to_bool_or_true(f) && static_cast<bool>(acquire_lock(static_cast<const pointer_base&>(*this)));
          return {};
        }

        callback_ret<R> operator()(const callback_tag_move& op) const noexcept
        {
          void* const dp = &op.dst;
          void* const sp = &op.src;
          assert(sp != dp && "move constructing to the same address is illegal!");

          if (callback_stored_internally<callback_impl, storage_t>::value)
          {
            assert(sp == this && "move constructor doesn't apply to this type!");

            ::new (dp) callback_impl{std::move(*this)};
            this->~callback_impl();
          }
          else
          {
            auto** const spp = static_cast<callback_impl**>(sp);
            assert(*spp == this && "move constructor doesn't apply to this type!");

            *static_cast<callback_impl**>(dp) = *spp;
            *spp = nullptr;
          }
          return {};
        }

        callback_ret<R> operator()(const callback_tag_clone& op) const
        {
          void* const dp = &op.dst;

          if (callback_stored_internally<callback_impl, storage_t>::value)
            ::new (dp) callback_impl{*this};
          else
            *static_cast<callback_impl**>(dp) = new callback_impl{*this};
          return {};
        }

        callback_ret<R> operator()(const callback_tag_delete&) const
        {
          if (callback_stored_internally<callback_impl, storage_t>::value)
            this->~callback_impl();
          else
            delete this;
          return {};
        }

      private:
        static callback_ret<R> invoke_method(const storage_t& s, callback_method<Args...>&& call)
        {
          const void* const ip = &s;
          auto* const that = callback_stored_internally<callback_impl, storage_t>::value
            ? static_cast<const callback_impl*>(ip)
            : *static_cast<const callback_impl* const *>(ip)
            ;

          return boost::apply_visitor(*that, call);
        }

      public:
        static callback_method_invoker<R, Args...> construct(storage_t& s, LockablePtr p, F f)
        {
          void* const dp = &s;

          if (callback_stored_internally<callback_impl, storage_t>::value)
            ::new (dp) callback_impl{std::forward<LockablePtr>(p), std::forward<F>(f)};
          else
            *static_cast<callback_impl**>(dp) = new callback_impl{std::forward<LockablePtr>(p), std::forward<F>(f)};
          return invoke_method;
        }
    };
  }

  template <typename R, typename... Args>
  class callback<R(Args...)>
  {
    public:
      constexpr callback() noexcept = default;
      constexpr callback(std::nullptr_t) noexcept {}

      callback(const callback& other)
        : invoker([&] {
            if (other.invoker)
              other.invoker(other.storage, detail::callback_tag_clone{storage});
            return other.invoker;
          }())
      {
      }

      callback(callback&& other) noexcept
        : invoker([&] {
            auto invoke = other.invoker;
            if (invoke)
            {
              invoke(other.storage, detail::callback_tag_move{std::move(other.storage), storage});
              other.invoker = nullptr;
            }
            return invoke;
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
        : invoker([&] {
            using impl_t = detail::callback_impl<detail::always_valid_ptr, F, R, Args...>;
            return impl_t::construct(storage, {}, std::forward<F>(f));
          }())
      {
      }

      template <typename LockablePtr, typename F
        , typename = typename std::enable_if<!std::is_same<F, callback>::value &&
           (std::is_convertible<typename std::result_of<F(Args...)>::type, R>::value
         || std::is_void<R>::value)
         >::type>
      callback(F f, LockablePtr p)
        : invoker([&] {
            using impl_t = detail::callback_impl<LockablePtr, F, R, Args...>;
            return acquire_lock(p)
                ? impl_t::construct(storage, std::forward<LockablePtr>(p), std::forward<F>(f))
                : nullptr
                ;
          }())
      {
      }

      template <typename LockablePtr, typename F>
      callback(F f, LockablePtr p
          , typename std::enable_if<!std::is_same<F, callback>::value &&
              (std::is_convertible<typename std::result_of<F(typename std::pointer_traits<LockablePtr>::element_type*, Args...)>::type, R>::value
            || std::is_void<R>::value)
            >::type* = nullptr)
        : invoker([&] {
            using impl_t = detail::callback_impl<LockablePtr, F, R, Args...>;
            return acquire_lock(p)
                ? impl_t::construct(storage, std::forward<LockablePtr>(p), std::forward<F>(f))
                : nullptr
                ;
          }())
      {
      }

      callback& operator=(callback rhs) noexcept
      {
        *this = nullptr;
        if (rhs.invoker)
        {
          rhs.invoker(rhs.storage, detail::callback_tag_move{std::move(rhs.storage), storage});
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
          invoke(storage, detail::callback_tag_delete{});
        }
        return *this;
      }

      explicit operator bool() const noexcept
      {
        bool is_valid = false;
        if (invoker)
          invoker(storage, detail::callback_tag_is_valid{is_valid});
        return is_valid;
      }

      detail::callback_ret<R> operator()(Args... args) const
      {
        if (!invoker)
          throw std::bad_function_call();
        return invoker(storage, detail::callback_tag_invoke<Args...>{std::forward<Args>(args)...});
      }

    private:
      detail::callback_method_invoker<R, Args...> invoker = nullptr;
      detail::storage_t                           storage;
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

  callback<void (int, char)> w{S{}};
  callback<void (int, char)> x(some_f);
  callback<void (int, char)> y{x};
  callback<void (int, char)> z{std::move(x)};

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
