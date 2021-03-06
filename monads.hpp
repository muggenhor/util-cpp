/*
 * Copyright (C) 2018  Giel van Schijndel
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

#ifndef INCLUDED_MONADS_HPP
#define INCLUDED_MONADS_HPP

#include <functional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace util
{
  template <typename> class unexpected;
  template <typename, typename> class expected;
}

namespace monad
{
  template <typename> struct is_monad : std::false_type {};
  template <typename T, typename E>
  struct is_monad<::util::expected<T, E>> : std::true_type {};

  template <typename T>
  constexpr inline bool is_monad_v = is_monad<T>::value;

  template <typename T>
  using wrap_monad = std::conditional_t<is_monad_v<T>, T, ::util::expected<T, std::error_code>>;

  template <typename T>
  constexpr bool has_value(const T& v) noexcept
  {
    if constexpr (is_monad_v<T>)
      return v.has_value();
    else
      return true;
  }

  template <typename T>
  constexpr decltype(auto) get_value(T&& v) noexcept
  {
    if constexpr (is_monad_v<std::decay_t<T>>)
      return *std::forward<T>(v);
    else
      return std::forward<T>(v);
  }

  // constexpr: not possible (now) because std::error_code isn't literal
  inline auto get_error() noexcept
  {
    return std::error_code();
  }

  template <typename T, typename... Ts>
  std::error_code get_error(T&& v, Ts&&... vs) noexcept
  {
    if constexpr (is_monad_v<std::decay_t<T>>)
      if (!has_value(v))
        return std::forward<T>(v).error();
    return get_error(std::forward<Ts>(vs)...);
  }

  template <typename F, typename... Ts>
  constexpr auto map(F&& f, Ts&&... vs)
      noexcept(noexcept(std::invoke(std::forward<F>(f), get_value(std::forward<Ts>(vs))...)))
   -> wrap_monad<decltype(std::invoke(std::forward<F>(f), get_value(std::forward<Ts>(vs))...))>
  {
    if ((!has_value(vs) || ...))
      return ::util::unexpected(get_error(std::forward<Ts>(vs)...));
    if constexpr (std::is_void_v<decltype(std::invoke(std::forward<F>(f), get_value(std::forward<Ts>(vs))...))>)
    {
      std::invoke(std::forward<F>(f), get_value(std::forward<Ts>(vs))...);
      return {};
    }
    else
    {
      return std::invoke(std::forward<F>(f), get_value(std::forward<Ts>(vs))...);
    }
  }

  template <typename F, typename Tuple>
  constexpr auto apply(F&& f, Tuple&& t)
  {
    return map([&f](auto&& t) {
          return std::apply(std::forward<F>(f), std::forward<decltype(t)>(t));
        }, std::forward<Tuple>(t));
  }

  template <typename T, typename F>
  constexpr auto transform(T&& v, F&& f)
      noexcept(noexcept(map(std::forward<F>(f), std::forward<T>(v))))
  {
    return map(std::forward<F>(f), std::forward<T>(v));
  }

  template <typename C, typename F>
  constexpr wrap_monad<C> collect(const std::size_t count, F&& f)
  {
    wrap_monad<C> r;
    get_value(r).reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
      if (auto e = transform(std::invoke(std::forward<F>(f)),
            [&c = get_value(r)] (auto&& v) {
              c.insert(c.end(), std::forward<decltype(v)>(v));
            });
          !has_value(e))
        return ::util::unexpected(get_error(std::move(e)));
    }
    return r;
  }

  namespace detail
  {
    template <typename T, bool has_constructor>
    struct do_construct
    {
      template <typename... Args>
      constexpr T operator()(Args&&... args) noexcept(noexcept(T{std::forward<Args>(args)...}))
      {
        return T{std::forward<Args>(args)...};
      }
    };

    template <typename T>
    struct do_construct<T, true>
    {
      template <typename... Args>
      constexpr T operator()(Args&&... args) noexcept(noexcept(T(std::forward<Args>(args)...)))
      {
        return T(std::forward<Args>(args)...);
      }
    };
  }

  template <typename T, typename... Args>
  constexpr auto construct(Args&&... args)
      noexcept(noexcept(map(detail::do_construct<T, std::is_constructible_v<T, Args...>>(), std::forward<Args>(args)...)))
  {
    return map(detail::do_construct<T, std::is_constructible_v<T, Args...>>(), std::forward<Args>(args)...);
  }

  template <typename T, typename Tuple>
  constexpr auto make_from_tuple(Tuple&& t)
  {
    return std::apply([] (auto&&... args) {
        return construct<T>(std::forward<decltype(args)>(args)...);
      }, std::forward<Tuple>(t));
  }

  namespace detail
  {
    template <typename V, typename F>
    constexpr auto sequence_helper(const V& v, F&& f)
    {
      return std::make_tuple(transform(v, [&f](auto&&) { return std::invoke(std::forward<F>(f)); }));
    }

    template <typename V, typename F, typename... Fs>
    constexpr auto sequence_helper(const V& v, F&& f, Fs&&... fs)
    {
      auto r  = transform(v, [&f](auto&&) { return std::invoke(std::forward<F>(f)); });
      auto rs = sequence_helper(r, std::forward<Fs>(fs)...);
      return std::tuple_cat(std::make_tuple(std::move(r)), std::move(rs));
    }
  }

  template <typename F>
  constexpr auto sequence(F&& f) noexcept(noexcept(std::make_tuple(map(std::forward<F>(f)))))
  {
    return std::make_tuple(map(std::forward<F>(f)));
  }

  template <typename F, typename... Fs>
  constexpr auto sequence(F&& f, Fs&&... fs)
  {
    auto r  = std::invoke(std::forward<F>(f));
    auto rs = detail::sequence_helper(r, std::forward<Fs>(fs)...);
    return std::tuple_cat(std::make_tuple(std::move(r)), std::move(rs));
  }
}

#endif /* INCLUDED_MONADS_HPP */
