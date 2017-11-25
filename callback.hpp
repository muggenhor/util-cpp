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
#include <cstddef>
#include <functional>
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

    template <typename... Args>
    struct callback_helper
    {
      template <typename R, typename F>
      typename std::enable_if<is_callable<F, Args...>::value, R>::type
      static do_invoke_impl(F&& f, Args... args)
      {
        return static_cast<R>(std::forward<F>(f)(std::forward<Args>(args)...));
      }

      template <typename R, typename O, typename F>
      typename std::enable_if<is_callable<F, Args...>::value, R>::type
      static do_invoke_impl(O&&, F&& f, Args... args)
      {
        return static_cast<R>(std::forward<F>(f)(std::forward<Args>(args)...));
      }

      template <typename R, typename O, typename F>
      typename std::enable_if<is_callable<F, O, Args...>::value, R>::type
      static do_invoke_impl(O&& that, F&& f, Args... args)
      {
        return static_cast<R>(std::forward<F>(f)(std::forward<O>(that), std::forward<Args>(args)...));
      }

      template <typename R, typename FR, typename O>
      static R do_invoke_impl(O* that, FR O::* f, Args... args)
      {
        return static_cast<R>((that->*f)(std::forward<Args>(args)...));
      }

      template <typename R, typename RawAddress, typename O, typename F>
      typename std::enable_if<!std::is_same<RawAddress, void>::value, R>::type
      static do_invoke_dereference(O&& that, F&& f, Args... args)
      {
        using ::util::to_address;
        return do_invoke_impl<R>(to_address(std::forward<O>(that)), std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename R, typename RawAddress, typename O, typename F>
      typename std::enable_if<std::is_same<RawAddress, void>::value, R>::type
      static do_invoke_dereference(O&&, F&& f, Args... args)
      {
        return do_invoke_impl<R>(std::forward<F>(f), std::forward<Args>(args)...);
      }

      template <typename R, typename O, typename F, std::size_t... I>
      static R do_invoke_expand(O&& that, F&& f, std::tuple<Args...>& args, index_sequence<I...>)
      {
        using ::util::to_address;
        using raw_address_t = decltype(to_address(std::forward<O>(that)));
        return do_invoke_dereference<R, raw_address_t>(std::forward<O>(that), std::forward<F>(f), std::get<I>(std::move(args))...);
      }

      template <typename R, typename O, typename F>
      static R do_invoke(O&& that, F&& f, std::tuple<Args...>& args)
      {
        return do_invoke_expand<R>(std::forward<O>(that), std::forward<F>(f), args, make_index_sequence<sizeof...(Args)>{});
      }
    };

    struct always_valid_ptr {};
    inline constexpr bool acquire_lock(const always_valid_ptr&)
    {
      return true;
    }

    template <typename R, typename... Args>
    struct callback_deleter;

    template <typename R, typename... Args>
    using callback_ptr = std::unique_ptr<void, detail::callback_deleter<R, Args...>>; 

    template <typename R, typename... Args>
    using callback_method = boost::variant<
        std::tuple<Args...>           // invoke
      , bool&                         // is_valid
      , callback_ptr<R, Args...>&     // clone
      , callback_deleter<R, Args...>  // delete
      >;

    template <typename R>
    struct callbackret_s
    {
      using type = boost::optional<R>;
    };

    template <>
    struct callbackret_s<void>
    {
      using type = void;
    };

    template <typename R>
    using callback_ret = typename callbackret_s<R>::type;

    template <typename R>
    callback_ret<R> empty_callback_ret()
    {
      return {};
    }

    template <>
    void empty_callback_ret<void>()
    {
    }

    template <typename R, typename... Args>
    using callback_method_invoker = callback_ret<R> (*)(const void* that, callback_method<R, Args...>&& call);

    // Functions as deleter for unique_ptr and simultaneously as dispatcher to the type-erased callback implementation
    template <typename R, typename... Args>
    struct callback_deleter
    {
      constexpr callback_deleter(callback_method_invoker<R, Args...> invoker) noexcept
        : invoker(invoker)
      {
      }

      // deleter
      void operator()(void* p) const
      {
        invoke_method(p, *this);
      }

      callback_ret<R> invoke_method(const void* that, callback_method<R, Args...>&& call) const
      {
        return this->invoker(that, std::move(call));
      }

      callback_method_invoker<R, Args...> invoker;
    };

    template <typename R, typename... Args>
    struct callback_invoker_helper
    {
      static R invoke(const callback_ptr<R, Args...>& that, Args... args)
      {
        return *that.get_deleter().invoke_method(that.get(), std::forward_as_tuple(std::forward<Args>(args)...));
      }
    };

    template <typename... Args>
    struct callback_invoker_helper<void, Args...>
    {
      static void invoke(const callback_ptr<void, Args...>& that, Args... args)
      {
        that.get_deleter().invoke_method(that.get(), std::forward_as_tuple(std::forward<Args>(args)...));
      }
    };

    template <typename R, typename... Args>
    R invoke(const callback_ptr<R, Args...>& that, Args... args)
    {
      return callback_invoker_helper<R, Args...>::invoke(that, std::forward<Args>(args)...);
    }

    template <typename T>
    struct pointer_wrapper
    {
    public:
      constexpr pointer_wrapper(T p) : pointer(p) {}

      constexpr operator const T&() const
      {
        return pointer;
      }

    private:
      T pointer;
    };

    template <typename T>
    T acquire_lock(const pointer_wrapper<T>& p)
    {
      using ::util::acquire_lock;
      return acquire_lock(static_cast<const T&>(p));
    }

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

    template <typename LockablePtr, typename F, typename R, typename... Args>
    class callback_impl final : // inherit for empty-base optimisation
                                 private wrap_pointer_t<LockablePtr>
    {
      public:
        using base_t = wrap_pointer_t<LockablePtr>;

        callback_impl(LockablePtr p, F f)
          : base_t(std::forward<LockablePtr>(p))
          , f(std::forward<F>(f))
        {}

        using result_type = callback_ret<R>;

        callback_ret<R> operator()(std::tuple<Args...>& args) const
        {
          using ::util::acquire_lock;
          if (auto i = acquire_lock(static_cast<const base_t&>(*this)))
          {
            return callback_helper<Args...>::template do_invoke<R>(std::forward<decltype(i)>(i), f, args);
          }
          else
          {
            throw std::bad_function_call();
          }
        }

        callback_ret<R> operator()(bool& is_valid) const noexcept
        {
          using ::util::acquire_lock;
          is_valid = static_cast<bool>(f) && static_cast<bool>(acquire_lock(static_cast<const base_t&>(*this)));
          return empty_callback_ret<R>();
        }

        callback_ret<R> operator()(callback_ptr<R, Args...>& clone) const
        {
          clone = { new callback_impl(*this), { &invoke_method } };
          return empty_callback_ret<R>();
        }

        callback_ret<R> operator()(const callback_deleter<R, Args...>&) const
        {
          delete this;
          return empty_callback_ret<R>();
        }

        static callback_ret<R> invoke_method(const void* that, callback_method<R, Args...>&& call)
        {
          return boost::apply_visitor(*static_cast<const callback_impl*>(that), call);
        }

      private:
        F f;
    };
  }

  template <typename FunctionSignature>
  class callback;

  template <typename R, typename... Args>
  class callback<R(Args...)>
  {
    private:
      using deleter = detail::callback_deleter<R, Args...>;
      using pointer = detail::callback_ptr<R, Args...>;

    public:
      constexpr callback() noexcept = default;
      constexpr callback(std::nullptr_t) noexcept {}

      callback(const callback& other)
        : impl([&other] {
            pointer ptr{nullptr, {nullptr}};
            if (other.impl)
              other.impl.get_deleter().invoke_method(other.impl.get(), ptr);
            return ptr;
          }())
      {
      }

      callback(callback&& other) noexcept = default;

      template <typename F
        , typename = typename std::enable_if<!std::is_same<F, callback>::value>::type
        , typename = typename std::enable_if<
            std::is_convertible<typename std::result_of<F(Args...)>::type, R>::value
         || std::is_void<R>::value
         >::type>
      callback(F f)
        : impl([&f] {
            using impl_t = detail::callback_impl<detail::always_valid_ptr, F, R, Args...>;
            return pointer{new impl_t{{}, std::forward<F>(f)}, deleter{&impl_t::invoke_method}};
          }())
      {
      }

      template <typename LockablePtr, typename F
        , typename = typename std::enable_if<!std::is_same<F, callback>::value &&
           (std::is_convertible<typename std::result_of<F(Args...)>::type, R>::value
         || std::is_void<R>::value)
         >::type>
      callback(LockablePtr p, F f)
        : impl([&p, &f] {
            using impl_t = detail::callback_impl<LockablePtr, F, R, Args...>;
            return pointer{
                acquire_lock(p)
                  ? new impl_t{std::forward<LockablePtr>(p), std::forward<F>(f)}
                  : nullptr
                  , deleter{&impl_t::invoke_method}};
          }())
      {
      }

      template <typename LockablePtr, typename F>
      callback(LockablePtr p, F f
          , typename std::enable_if<!std::is_same<F, callback>::value &&
              (std::is_convertible<typename std::result_of<F(typename std::pointer_traits<LockablePtr>::element_type*, Args...)>::type, R>::value
            || std::is_void<R>::value)
            >::type* = nullptr)
        : impl([&p, &f] {
            using impl_t = detail::callback_impl<LockablePtr, F, R, Args...>;
            return pointer{
                acquire_lock(p)
                  ? new impl_t{std::forward<LockablePtr>(p), std::forward<F>(f)}
                  : nullptr
                  , deleter{&impl_t::invoke_method}};
          }())
      {
      }

      friend void swap(callback& lhs, callback rhs) noexcept
      {
        swap(lhs.impl, rhs.impl);
      }

      callback& operator=(callback rhs)
      {
        swap(*this, rhs);
        return *this;
      }

      callback& operator=(std::nullptr_t)
      {
        impl.reset();
        return *this;
      }

      explicit operator bool() const noexcept
      {
        bool is_valid = false;
        if (impl)
          impl.get_deleter().invoke_method(impl.get(), is_valid);
        return is_valid;
      }

      R operator()(Args... args) const
      {
        if (!impl)
          throw std::bad_function_call();
        return invoke(impl, std::forward<Args>(args)...);
      }

    private:
      pointer impl;
  };
}

#ifdef TEST
#include <cassert>
#include <iostream>

namespace
{
  int some_f(int, char) { return 0; }
}

int main()
{
  using namespace util;

  callback<void (int, char)> x(some_f);
  callback<void (int, char)> y{x};
  callback<void (int, char)> z{std::move(x)};

  y(0, 'a');
  z(1, 'b');

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
