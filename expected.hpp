/*
 * Copyright (C) 2018  Giel van Schijndel
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef INCLUDED_EXPECTED_HPP
#define INCLUDED_EXPECTED_HPP

#include <cassert>
#include <initializer_list>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>
#include "monads.hpp"

// Based on p0323r7

namespace util
{
  template <typename E>
  class unexpected
  {
  public:
    template <typename... Args
      , typename = std::enable_if_t<std::is_constructible_v<E, Args...>>>
    constexpr explicit unexpected(std::in_place_t, Args&&... args) noexcept(noexcept(E(std::forward<Args>(args)...)))
      : val(std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args
      , typename = std::enable_if_t<std::is_constructible_v<E, std::initializer_list<U>&, Args...>>>
    constexpr explicit unexpected(std::in_place_t, std::initializer_list<U> il, Args&&... args)
      noexcept(noexcept(E(il, std::forward<Args>(args)...)))
      : val(il, std::forward<Args>(args)...)
    {
    }

    template <typename Err = E
      , typename = std::enable_if_t<std::is_constructible_v<E, Err>>
      , typename = std::enable_if_t<!std::is_same_v<std::decay_t<Err>, std::in_place_t>>
      , typename = std::enable_if_t<!std::is_same_v<std::decay_t<Err>, unexpected>>
      >
    constexpr explicit unexpected(Err&& e) noexcept(noexcept(E(std::forward<Err>(e))))
      : val(std::forward<Err>(e))
    {
    }

    template <typename Err
      , std::enable_if_t<
              std::is_constructible_v<E, const Err&>
           && !std::is_constructible_v<E, unexpected<Err>&>
           && !std::is_constructible_v<E, unexpected<Err>&&>
           && !std::is_constructible_v<E, const unexpected<Err>&>
           && !std::is_constructible_v<E, const unexpected<Err>&&>
           && !std::is_convertible_v<unexpected<Err>&, E>
           && !std::is_convertible_v<unexpected<Err>&&, E>
           && !std::is_convertible_v<const unexpected<Err>&, E>
           && !std::is_convertible_v<const unexpected<Err>&&, E>
           // non-explicit-ness propagation
           && std::is_convertible_v<const Err&, E>
          , bool> = false
      >
    constexpr unexpected(const unexpected<Err>& rhs) noexcept(std::is_nothrow_constructible_v<E, const Err&>)
      : val(rhs.val)
    {
    }

    template <typename Err
      , std::enable_if_t<
              std::is_constructible_v<E, const Err&>
           && !std::is_constructible_v<E, unexpected<Err>&>
           && !std::is_constructible_v<E, unexpected<Err>&&>
           && !std::is_constructible_v<E, const unexpected<Err>&>
           && !std::is_constructible_v<E, const unexpected<Err>&&>
           && !std::is_convertible_v<unexpected<Err>&, E>
           && !std::is_convertible_v<unexpected<Err>&&, E>
           && !std::is_convertible_v<const unexpected<Err>&, E>
           && !std::is_convertible_v<const unexpected<Err>&&, E>
           // explicit-ness propagation
           && !std::is_convertible_v<const Err&, E>
          , bool> = false
      >
    explicit constexpr unexpected(const unexpected<Err>& rhs) noexcept(std::is_nothrow_constructible_v<E, const Err&>)
      : val(rhs.val)
    {
    }

    template <typename Err
      , std::enable_if_t<
              std::is_constructible_v<E, Err&&>
           && !std::is_constructible_v<E, unexpected<Err>&>
           && !std::is_constructible_v<E, unexpected<Err>&&>
           && !std::is_constructible_v<E, const unexpected<Err>&>
           && !std::is_constructible_v<E, const unexpected<Err>&&>
           && !std::is_convertible_v<unexpected<Err>&, E>
           && !std::is_convertible_v<unexpected<Err>&&, E>
           && !std::is_convertible_v<const unexpected<Err>&, E>
           && !std::is_convertible_v<const unexpected<Err>&&, E>
           // non-explicit-ness propagation
           && std::is_convertible_v<Err&&, E>
          , bool> = false
      >
    constexpr unexpected(const unexpected<Err>& rhs) noexcept(std::is_nothrow_constructible_v<E, Err&&>)
      : val(std::move(rhs.val))
    {
    }

    template <typename Err
      , std::enable_if_t<
              std::is_constructible_v<E, Err&&>
           && !std::is_constructible_v<E, unexpected<Err>&>
           && !std::is_constructible_v<E, unexpected<Err>&&>
           && !std::is_constructible_v<E, const unexpected<Err>&>
           && !std::is_constructible_v<E, const unexpected<Err>&&>
           && !std::is_convertible_v<unexpected<Err>&, E>
           && !std::is_convertible_v<unexpected<Err>&&, E>
           && !std::is_convertible_v<const unexpected<Err>&, E>
           && !std::is_convertible_v<const unexpected<Err>&&, E>
           // explicit-ness propagation
           && !std::is_convertible_v<Err&&, E>
          , bool> = false
      >
    explicit constexpr unexpected(const unexpected<Err>& rhs) noexcept(std::is_nothrow_constructible_v<E, Err&&>)
      : val(std::move(rhs.val))
    {
    }

    template <typename G = E
      , std::enable_if_t<
          std::is_assignable_v<E&, const G&>
        , bool> = false
      >
    unexpected& operator=(const unexpected<G>& e)
    {
      val = e.val;
      return *this;
    }

    template <typename G = E
      , std::enable_if_t<
          std::is_assignable_v<E&, G&&>
        , bool> = false
      >
    unexpected& operator=(unexpected<G>&& e)
    {
      val = std::move(e.val);
      return *this;
    }

    constexpr const E&  value() const&  noexcept { return           val ; }
    constexpr       E&  value()      &  noexcept { return           val ; }
    constexpr const E&& value() const&& noexcept { return std::move(val); }
    constexpr       E&& value()      && noexcept { return std::move(val); }

    void swap(unexpected& other) noexcept(std::is_nothrow_swappable_v<E>)
    {
      using std::swap;
      swap(this->val, other.val);
    }

    template <typename E2>
    constexpr bool operator==(const unexpected<E2>& rhs) const
    {
      return this->value() == rhs.value();
    }

    template <typename E2>
    constexpr bool operator!=(const unexpected<E2>& rhs) const
    {
      return this->value() != rhs.value();
    }

    friend void swap(unexpected& lhs, unexpected& rhs) noexcept(noexcept(lhs.swap(rhs)))
    {
      lhs.swap(rhs);
    }

  private:
    E val;
  };

  template <typename E>
  unexpected(E) -> unexpected<E>;

  struct unexpect_t {
    explicit unexpect_t() = default;
  };
  inline constexpr unexpect_t unexpect{};

  template <typename T, typename E>
  class expected
  {
  public:
    using value_type = T;
    using error_type = E;
    using unexpected_type = unexpected<E>;

    template <typename U>
    using rebind = expected<U, error_type>;

  private:
    using storage_type = std::variant<value_type, unexpected_type>;
  public:

    template <typename = std::enable_if_t<std::is_default_constructible_v<T>>>
    constexpr expected()
      : content_(std::in_place_type<value_type>)
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<T, const U&>
           && !std::is_constructible_v<T, expected<U, G>&>
           && !std::is_constructible_v<T, expected<U, G>&&>
           && !std::is_constructible_v<T, const expected<U, G>&>
           && !std::is_constructible_v<T, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, T>
           && !std::is_convertible_v<expected<U, G>&&, T>
           && !std::is_convertible_v<const expected<U, G>&, T>
           && !std::is_convertible_v<const expected<U, G>&&, T>
           && std::is_constructible_v<E, const G&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // non-explicit-ness propagation
           && (std::is_convertible_v<const U&, T> && std::is_convertible_v<const G&, E>)
          , bool> = false
      >
    constexpr expected(const expected<U, G>& rhs) noexcept(
          std::is_nothrow_constructible_v<T, const U&>
       && std::is_nothrow_constructible_v<E, const G&>)
      : content_(rhs ? storage_type(std::in_place_type<value_type>, *rhs) : storage_type(std::in_place_type<unexpected_type>, rhs.error()))
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<T, const U&>
           && !std::is_constructible_v<T, expected<U, G>&>
           && !std::is_constructible_v<T, expected<U, G>&&>
           && !std::is_constructible_v<T, const expected<U, G>&>
           && !std::is_constructible_v<T, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, T>
           && !std::is_convertible_v<expected<U, G>&&, T>
           && !std::is_convertible_v<const expected<U, G>&, T>
           && !std::is_convertible_v<const expected<U, G>&&, T>
           && std::is_constructible_v<E, const G&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // explicit-ness propagation
           && !(std::is_convertible_v<const U&, T> && std::is_convertible_v<const G&, E>)
          , bool> = false
      >
    explicit constexpr expected(const expected<U, G>& rhs) noexcept(
          std::is_nothrow_constructible_v<T, const U&>
       && std::is_nothrow_constructible_v<E, const G&>)
      : content_(rhs ? storage_type(std::in_place_type<value_type>, *rhs) : storage_type(std::in_place_type<unexpected_type>, rhs.error()))
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<T, U&&>
           && !std::is_constructible_v<T, expected<U, G>&>
           && !std::is_constructible_v<T, expected<U, G>&&>
           && !std::is_constructible_v<T, const expected<U, G>&>
           && !std::is_constructible_v<T, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, T>
           && !std::is_convertible_v<expected<U, G>&&, T>
           && !std::is_convertible_v<const expected<U, G>&, T>
           && !std::is_convertible_v<const expected<U, G>&&, T>
           && std::is_constructible_v<E, G&&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // non-explicit-ness propagation
           && (std::is_convertible_v<U&&, T> && std::is_convertible_v<G&&, E>)
          , bool> = false
      >
    constexpr expected(expected<U, G>&& rhs) noexcept(
          std::is_nothrow_constructible_v<T, U&&>
       && std::is_nothrow_constructible_v<E, G&&>)
      : content_(rhs ? storage_type(std::in_place_type<value_type>, std::move(*rhs)) : storage_type(std::in_place_type<unexpected_type>, std::move(rhs.error())))
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<T, U&&>
           && !std::is_constructible_v<T, expected<U, G>&>
           && !std::is_constructible_v<T, expected<U, G>&&>
           && !std::is_constructible_v<T, const expected<U, G>&>
           && !std::is_constructible_v<T, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, T>
           && !std::is_convertible_v<expected<U, G>&&, T>
           && !std::is_convertible_v<const expected<U, G>&, T>
           && !std::is_convertible_v<const expected<U, G>&&, T>
           && std::is_constructible_v<E, G&&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // explicit-ness propagation
           && !(std::is_convertible_v<U&&, T> && std::is_convertible_v<G&&, E>)
          , bool> = false
      >
    explicit constexpr expected(expected<U, G>&& rhs) noexcept(
          std::is_nothrow_constructible_v<T, U&&>
       && std::is_nothrow_constructible_v<E, G&&>)
      : content_(rhs ? storage_type(std::in_place_type<value_type>, std::move(*rhs)) : storage_type(std::in_place_type<unexpected_type>, std::move(rhs.error())))
    {
    }

    template <typename U = T,
      std::enable_if_t<
        std::is_constructible_v<T, U&&>
     && !std::is_same_v<std::decay_t<U>, std::in_place_t>
     && !std::is_same_v<std::decay_t<U>, expected<T, E>>
     && !std::is_same_v<std::decay_t<U>, unexpected<T>>
     // explicit-ness propagation
     && std::is_convertible_v<U&&, T>
      , bool> = false
    >
    constexpr expected(U&& v) noexcept(noexcept(storage_type(std::in_place_type<value_type>, std::forward<U>(v))))
      : content_(std::in_place_type<value_type>, std::forward<U>(v))
    {
    }

    template <typename U = T,
      std::enable_if_t<
        std::is_constructible_v<T, U&&>
     && !std::is_same_v<std::decay_t<U>, std::in_place_t>
     && !std::is_same_v<std::decay_t<U>, expected<T, E>>
     && !std::is_same_v<std::decay_t<U>, unexpected<T>>
     // explicit-ness propagation
     && !std::is_convertible_v<U&&, T>
      , bool> = false
    >
    explicit constexpr expected(U&& v) noexcept(noexcept(storage_type(std::in_place_type<value_type>, std::forward<U>(v))))
      : content_(std::in_place_type<value_type>, std::forward<U>(v))
    {
    }

    template <typename G = E>
    constexpr expected(const unexpected<G>& e) noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, e)))
      : content_(std::in_place_type<unexpected_type>, e)
    {
    }

    template <typename G = E>
    constexpr expected(unexpected<G>&& e) noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, std::move(e.value()))))
      : content_(std::in_place_type<unexpected_type>, std::move(e.value()))
    {
    }

    template <typename... Args,
      typename = std::enable_if_t<std::is_constructible_v<T, Args...>>>
    constexpr explicit expected(std::in_place_t, Args&&... args) noexcept(noexcept(storage_type(std::in_place_type<value_type>, std::forward<Args>(args)...)))
      : content_(std::in_place_type<value_type>, std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args,
      typename = std::enable_if_t<std::is_constructible_v<T, std::initializer_list<U>&, Args...>>>
    constexpr explicit expected(std::in_place_t, std::initializer_list<U> il, Args&&... args)
      noexcept(noexcept(storage_type(std::in_place_type<value_type>, il, std::forward<Args>(args)...)))
      : content_(std::in_place_type<value_type>, il, std::forward<Args>(args)...)
    {
    }

    template <typename... Args,
      typename = std::enable_if_t<std::is_constructible_v<E, Args...>>>
    constexpr explicit expected(unexpect_t, Args&&... args)
      noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, std::in_place, std::forward<Args>(args)...)))
      : content_(std::in_place_type<unexpected_type>, std::in_place, std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args,
      typename = std::enable_if_t<std::is_constructible_v<E, std::initializer_list<U>&, Args...>>>
    constexpr explicit expected(unexpect_t, std::initializer_list<U> il, Args&&... args)
      noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, std::in_place, il, std::forward<Args>(args)...)))
      : content_(std::in_place_type<unexpected_type>, std::in_place, il, std::forward<Args>(args)...)
    {
    }

    template <typename U = T
      , std::enable_if_t<
          !std::is_same_v<std::decay_t<U>, expected>
       && !std::conjunction_v<std::is_scalar_v<T>, std::is_same_v<T, std::decay_t<U>>>
       && std::is_constructible_v<T, U>
       && std::is_assignable_v<T&, U>
       && std::is_nothrow_move_constructible_v<E>
        , bool> = false
      >
    expected& operator=(U&& rhs)
    {
      if (has_value())
      {
        **this = std::forward<U>(rhs);
      }
      else
      {
        if constexpr (std::is_nothrow_constructible_v<T, U>)
        {
          content_.template emplace<T>(std::forward<T>(rhs));
        }
        else
        {
          unexpected_type tmp(std::move(std::get<unexpected_type>(content_)));
          try
          {
            content_.template emplace<T>(std::forward<T>(rhs));
          }
          catch (...)
          {
            content_ = std::move(tmp);
            throw;
          }
        }
      }

      return *this;
    }

    template <typename G = E
      , std::enable_if_t<
          std::is_nothrow_copy_constructible_v<E>
       && std::is_copy_assignable_v<E>
        , bool> = false
      >
    expected& operator=(const unexpected<G>& e)
    {
      content_ = unexpected(e.value());
      return *this;
    }

    template <typename G = E
      , std::enable_if_t<
          std::is_nothrow_move_constructible_v<E>
       && std::is_move_assignable_v<E>
        , bool> = false
      >
    expected& operator=(unexpected<G>&& e)
    {
      content_ = unexpected(std::move(e.value()));
      return *this;
    }

    template <typename... Args>
    T& emplace(Args&&... args)
    {
      if (has_value())
      {
        content_ = T(std::forward<Args>(args)...);
        return **this;
      }
      else
      {
        if constexpr (std::is_nothrow_constructible_v<T, Args...>())
        {
          return content_.template emplace<T>(std::forward<Args>(args)...);
        }
        else if constexpr (std::is_nothrow_move_constructible_v<T>)
        {
          content_ = T(std::forward<Args>(args)...);
          return **this;
        }
        else
        {
          unexpected_type tmp(std::move(std::get<unexpected_type>(content_)));
          try
          {
            return content_.template emplace<T>(std::forward<Args>(args)...);
          }
          catch (...)
          {
            content_ = std::move(tmp);
            throw;
          }
        }
      }
    }

    template <typename U, typename... Args>
    T& emplace(std::initializer_list<U> il, Args&&... args)
    {
      if (has_value())
      {
        content_ = T(il, std::forward<Args>(args)...);
        return **this;
      }
      else
      {
        if constexpr (std::is_nothrow_constructible_v<T, Args...>())
        {
          return content_.template emplace<T>(il, std::forward<Args>(args)...);
        }
        else if constexpr (std::is_nothrow_move_constructible_v<T>)
        {
          content_ = T(il, std::forward<Args>(args)...);
          return **this;
        }
        else
        {
          unexpected_type tmp(std::move(std::get<unexpected_type>(content_)));
          try
          {
            return content_.template emplace<T>(il, std::forward<Args>(args)...);
          }
          catch (...)
          {
            content_ = std::move(tmp);
            throw;
          }
        }
      }
    }

    void swap(expected& other) noexcept(std::is_nothrow_swappable_v<storage_type>)
    {
      using std::swap;
      swap(this->content_, other.content_);
    }

    constexpr const value_type* operator->() const
    {
      return &**this;
    }

    constexpr value_type* operator->()
    {
      return &**this;
    }

    constexpr const T& operator*() const&
    {
      assert(has_value());
      return std::get<value_type>(content_);
    }

    constexpr T& operator*() &
    {
      assert(has_value());
      return std::get<value_type>(content_);
    }

    constexpr const T&& operator*() const&&
    {
      assert(has_value());
      return std::move(std::get<value_type>(content_));
    }

    constexpr T&& operator*() &&
    {
      assert(has_value());
      return std::move(std::get<value_type>(content_));
    }

    constexpr explicit operator bool() const noexcept
    {
      return has_value();
    }

    constexpr bool has_value() const noexcept
    {
      return std::holds_alternative<value_type>(content_);
    }

    constexpr const T& value() const&
    {
      if (!has_value())
        throw std::logic_error("precondition error: doesn't have value");
      return **this;
    }

    constexpr T& value() &
    {
      if (!has_value())
        throw std::logic_error("precondition error: doesn't have value");
      return **this;
    }

    constexpr const T&& value() const&&
    {
      if (!has_value())
        throw std::logic_error("precondition error: doesn't have value");
      return *std::move(*this);
    }

    constexpr T&& value() &&
    {
      if (!has_value())
        throw std::logic_error("precondition error: doesn't have value");
      return *std::move(*this);
    }

    constexpr const E& error() const&
    {
      assert(!has_value());
      return std::get<unexpected_type>(content_).value();
    }

    constexpr E& error() &
    {
      assert(!has_value());
      return std::get<unexpected_type>(content_).value();
    }

    constexpr const E&& error() const&&
    {
      assert(!has_value());
      return std::move(std::get<unexpected_type>(content_).value());
    }

    constexpr E&& error() &&
    {
      assert(!has_value());
      return std::move(std::get<unexpected_type>(content_).value());
    }

    template <typename U>
    constexpr T value_or(U&& v) const&
    {
      if (has_value())
        return **this;
      else
        return static_cast<T>(std::forward<U>(v));
    }

    template <typename U>
    constexpr T value_or(U&& v) &&
    {
      if (has_value())
        return std::move(**this);
      else
        return static_cast<T>(std::forward<U>(v));
    }

    template <typename F>
    constexpr auto map(F&& f) & noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<expected&>())))
    {
      return monad::map(std::forward<F>(f), *this);
    }

    template <typename F>
    constexpr auto map(F&& f) const & noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<const expected&>())))
    {
      return monad::map(std::forward<F>(f), *this);
    }

    template <typename F>
    constexpr auto map(F&& f) && noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<expected&&>())))
    {
      return monad::map(std::forward<F>(f), std::move(*this));
    }

    template <typename F>
    constexpr auto map(F&& f) const && noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<const expected&&>())))
    {
      return monad::map(std::forward<F>(f), std::move(*this));
    }

    template <typename F>
    constexpr auto apply(F&& f) & noexcept(noexcept(monad::apply(std::forward<F>(f), std::declval<expected&>())))
    {
      return monad::apply(std::forward<F>(f), *this);
    }

    template <typename F>
    constexpr auto apply(F&& f) const & noexcept(noexcept(monad::apply(std::forward<F>(f), std::declval<const expected&>())))
    {
      return monad::apply(std::forward<F>(f), *this);
    }

    template <typename F>
    constexpr auto apply(F&& f) && noexcept(noexcept(monad::apply(std::forward<F>(f), std::declval<expected&&>())))
    {
      return monad::apply(std::forward<F>(f), std::move(*this));
    }

    template <typename F>
    constexpr auto apply(F&& f) const && noexcept(noexcept(monad::apply(std::forward<F>(f), std::declval<const expected&&>())))
    {
      return monad::apply(std::forward<F>(f), std::move(*this));
    }

    friend void swap(expected& lhs, expected& rhs) noexcept(noexcept(lhs.swap(rhs)))
    {
      lhs.swap(rhs);
    }

  private:
    storage_type content_;
  };

  template <typename E>
  class expected<void, E>
  {
  public:
    using value_type = void;
    using error_type = E;
    using unexpected_type = unexpected<E>;

    template <typename U>
    using rebind = expected<U, error_type>;

  private:
    using storage_type = std::variant<std::monostate, unexpected_type>;
  public:

    constexpr expected() noexcept
      : content_(std::in_place_type<std::monostate>)
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<E, const G&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // non-explicit-ness propagation
           && std::is_convertible_v<const G&, E>
          , bool> = false
      >
    constexpr expected(const expected<U, G>& rhs) noexcept(
          std::is_nothrow_constructible_v<E, const G&>)
      : content_(rhs
          ? storage_type(std::in_place_type<std::monostate>, *rhs)
          : storage_type(std::in_place_type<unexpected_type>, rhs.error())
          )
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<E, const G&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // explicit-ness propagation
           && !std::is_convertible_v<const G&, E>
          , bool> = false
      >
    explicit constexpr expected(const expected<U, G>& rhs) noexcept(
          std::is_nothrow_constructible_v<E, const G&>)
      : content_(rhs
          ? storage_type(std::in_place_type<std::monostate>, *rhs)
          : storage_type(std::in_place_type<unexpected_type>, rhs.error())
          )
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<E, G&&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // non-explicit-ness propagation
           && std::is_convertible_v<G&&, E>
          , bool> = false
      >
    constexpr expected(expected<U, G>&& rhs) noexcept(
          std::is_nothrow_constructible_v<E, G&&>)
      : content_(rhs
          ? storage_type(std::in_place_type<std::monostate>, std::move(*rhs))
          : storage_type(std::in_place_type<unexpected_type>, std::move(rhs.error()))
          )
    {
    }

    template<typename U, typename G
      , std::enable_if_t<
              std::is_constructible_v<E, G&&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, expected<U, G>&&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&>
           && !std::is_constructible_v<unexpected<E>, const expected<U, G>&&>
           && !std::is_convertible_v<expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<expected<U, G>&&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&, unexpected<E>>
           && !std::is_convertible_v<const expected<U, G>&&, unexpected<E>>
           // explicit-ness propagation
           && !std::is_convertible_v<G&&, E>
          , bool> = false
      >
    explicit constexpr expected(expected<U, G>&& rhs) noexcept(
          std::is_nothrow_constructible_v<E, G&&>)
      : content_(rhs
          ? storage_type(std::in_place_type<std::monostate>, std::move(*rhs))
          : storage_type(std::in_place_type<unexpected_type>, std::move(rhs.error()))
          )
    {
    }

    template <typename G = E>
    constexpr expected(const unexpected<G>& e) noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, e)))
      : content_(std::in_place_type<unexpected_type>, e)
    {
    }

    template <typename G = E>
    constexpr expected(unexpected<G>&& e) noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, std::move(e.value()))))
      : content_(std::in_place_type<unexpected_type>, std::move(e.value()))
    {
    }

    constexpr explicit expected(std::in_place_t) noexcept
      : content_(std::in_place_type<std::monostate>)
    {
    }

    template <typename... Args,
      typename = std::enable_if_t<std::is_constructible_v<E, Args...>>>
    constexpr explicit expected(unexpect_t, Args&&... args)
      noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, std::in_place, std::forward<Args>(args)...)))
      : content_(std::in_place_type<unexpected_type>, std::in_place, std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args,
      typename = std::enable_if_t<std::is_constructible_v<E, std::initializer_list<U>&, Args...>>>
    constexpr explicit expected(unexpect_t, std::initializer_list<U> il, Args&&... args)
      noexcept(noexcept(storage_type(std::in_place_type<unexpected_type>, std::in_place, il, std::forward<Args>(args)...)))
      : content_(std::in_place_type<unexpected_type>, std::in_place, il, std::forward<Args>(args)...)
    {
    }

    template <typename G = E
      , std::enable_if_t<
          std::is_nothrow_copy_constructible_v<E>
       && std::is_copy_assignable_v<E>
        , bool> = false
      >
    expected& operator=(const unexpected<G>& e)
    {
      content_.template emplace<unexpected_type>(e.value());
      return *this;
    }

    template <typename G = E
      , std::enable_if_t<
          std::is_nothrow_move_constructible_v<E>
       && std::is_move_assignable_v<E>
        , bool> = false
      >
    expected& operator=(unexpected<G>&& e)
    {
      content_.template emplace<unexpected_type>(std::move(e.value()));
      return *this;
    }

    void emplace() noexcept
    {
      if (!has_value())
      {
        content_.template emplace<std::monostate>();
      }
    }

    void swap(expected& other) noexcept(std::is_nothrow_swappable_v<storage_type>)
    {
      using std::swap;
      swap(this->content_, other.content_);
    }

    constexpr explicit operator bool() const noexcept
    {
      return has_value();
    }

    constexpr bool has_value() const noexcept
    {
      return std::holds_alternative<std::monostate>(content_);
    }

    constexpr void value() const
    {
      if (!has_value())
        throw std::logic_error("precondition error: doesn't have value");
    }

    constexpr const E& error() const&
    {
      assert(!has_value());
      return std::get<unexpected_type>(content_).value();
    }

    constexpr E& error() &
    {
      assert(!has_value());
      return std::get<unexpected_type>(content_).value();
    }

    constexpr const E&& error() const&&
    {
      assert(!has_value());
      return std::move(std::get<unexpected_type>(content_).value());
    }

    constexpr E&& error() &&
    {
      assert(!has_value());
      return std::move(std::get<unexpected_type>(content_).value());
    }

    template <typename F>
    constexpr auto map(F&& f) & noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<expected&>())))
    {
      return monad::map(std::forward<F>(f), *this);
    }

    template <typename F>
    constexpr auto map(F&& f) const & noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<const expected&>())))
    {
      return monad::map(std::forward<F>(f), *this);
    }

    template <typename F>
    constexpr auto map(F&& f) && noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<expected&&>())))
    {
      return monad::map(std::forward<F>(f), std::move(*this));
    }

    template <typename F>
    constexpr auto map(F&& f) const && noexcept(noexcept(monad::map(std::forward<F>(f), std::declval<const expected&&>())))
    {
      return monad::map(std::forward<F>(f), std::move(*this));
    }

    friend void swap(expected& lhs, expected& rhs) noexcept(noexcept(lhs.swap(rhs)))
    {
      lhs.swap(rhs);
    }

  private:
    storage_type content_;
  };

  template <typename T1, typename E1, typename T2, typename E2>
  constexpr bool operator==(const expected<T1, E1>& lhs, const expected<T2, E2>& rhs)
  {
    if (lhs.has_value() != rhs.has_value())
      return false;
    if (!lhs.has_value())
      return lhs.error() == rhs.error();
    if constexpr (std::is_void_v<T1> && std::is_void_v<T2>)
      return true;
    else
      return *lhs == *rhs;
  }

  template <typename T1, typename E1, typename T2, typename E2>
  constexpr bool operator!=(const expected<T1, E1>& lhs, const expected<T2, E2>& rhs)
  {
    if (lhs.has_value() != rhs.has_value())
      return true;
    if (!lhs.has_value())
      return lhs.error() != rhs.error();
    if constexpr (std::is_void_v<T1> && std::is_void_v<T2>)
      return false;
    else
      return *lhs != *rhs;
  }

  template <typename T1, typename E1, typename T2
    , std::enable_if_t<std::is_void_v<T1> && std::is_void_v<T2>, bool> = false>
  constexpr bool operator==(const expected<T1, E1>& lhs, const T2& rhs)
  {
    return lhs.has_value() && *lhs == rhs;
  }

  template <typename T1, typename E1, typename T2
    , std::enable_if_t<std::is_void_v<T1> && std::is_void_v<T2>, bool> = false>
  constexpr bool operator==(const T2& lhs, const expected<T1, E1>& rhs)
  {
    return rhs == lhs;
  }

  template <typename T1, typename E1, typename T2
    , std::enable_if_t<std::is_void_v<T1> && std::is_void_v<T2>, bool> = false>
  constexpr bool operator!=(const expected<T1, E1>& lhs, const T2& rhs)
  {
    return !(lhs == rhs);
  }

  template <typename T1, typename E1, typename T2
    , std::enable_if_t<std::is_void_v<T1> && std::is_void_v<T2>, bool> = false>
  constexpr bool operator!=(const T2& lhs, const expected<T1, E1>& rhs)
  {
    return !(lhs == rhs);
  }

  template <typename T1, typename E1, typename E2>
  constexpr bool operator==(const expected<T1, E1>& lhs, const unexpected<E2>& rhs)
  {
    return !lhs.has_value() && unexpected(lhs.error()) == rhs;
  }

  template <typename T1, typename E1, typename E2>
  constexpr bool operator==(const unexpected<E2>& lhs, const expected<T1, E1>& rhs)
  {
    return rhs == lhs;
  }

  template <typename T1, typename E1, typename E2>
  constexpr bool operator!=(const expected<T1, E1>& lhs, const unexpected<E2>& rhs)
  {
    return lhs.has_value() || unexpected(rhs.error()) != rhs;
  }

  template <typename T1, typename E1, typename E2>
  constexpr bool operator!=(const unexpected<E2>& lhs, const expected<T1, E1>& rhs)
  {
    return rhs != lhs;
  }
}

#endif /* INCLUDED_EXPECTED_HPP */
