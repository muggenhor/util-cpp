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
  constexpr std::error_code get_error(T&& v, Ts&&... vs) noexcept
  {
    if constexpr (is_monad_v<std::decay_t<T>>)
      if (!has_value(v))
        return std::forward<T>(v).error();
    return get_error(std::forward<Ts>(vs)...);
  }

  template <typename F, typename... Ts>
  constexpr auto map(F&& f, Ts&&... vs)
      noexcept(noexcept(std::forward<F>(f)(get_value(std::forward<Ts>(vs))...)))
   -> wrap_monad<decltype(std::forward<F>(f)(get_value(std::forward<Ts>(vs))...))>
  {
    if ((has_value(vs) && ...))
      return std::forward<F>(f)(get_value(std::forward<Ts>(vs))...);
    else
      return ::util::unexpected(get_error(std::forward<Ts>(vs)...));
  }

  template <typename T, typename F>
  constexpr auto transform(T&& v, F&& f)
      noexcept(noexcept(map(std::forward<F>(f), std::forward<T>(v))))
  {
    return map(std::forward<F>(f), std::forward<T>(v));
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
}

#endif /* INCLUDED_MONADS_HPP */
