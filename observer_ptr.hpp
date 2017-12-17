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

#ifndef INCLUDED_OBSERVER_PTR_HPP
#define INCLUDED_OBSERVER_PTR_HPP

#include <memory>
#include <mutex>
#include <type_traits>
#include <unordered_set>

namespace util {

// Implementation details, not part of public API
namespace detail {
  class observable_deleter_base;

  struct observer_data
  {
    void*                    p = nullptr;
    observable_deleter_base* d = nullptr;
  };

  class observable_deleter_base
  {
  public:
    observable_deleter_base() = default;

    observable_deleter_base(observable_deleter_base&& rhs) noexcept : observers([&rhs] {
      std::lock_guard<decltype(rhs.mutex)> lock{rhs.mutex};
      return decltype(rhs.observers){std::move(rhs.observers)};
    }())
    {
    }

    observable_deleter_base& operator=(observable_deleter_base rhs) noexcept
    {
      std::lock_guard<decltype(mutex)> lock{mutex};
      assert(observers.empty());
      observers = std::move(rhs.observers);
      return *this;
    }

    ~observable_deleter_base()
    {
      assert(observers.empty());
    }

    void wipe() noexcept
    {
      std::lock_guard<decltype(mutex)> lock{mutex};

      for (auto& observer : observers)
      {
        assert(observer->d == this);
        observer->p = nullptr;
        observer->d = nullptr;
      }
      observers.clear();
    }

    void push(observer_data& o) noexcept
    {
      const auto observer_inserted = [&] {
        std::lock_guard<decltype(mutex)> lock{mutex};
        return observers.insert(&o).second;
      }();
      assert(observer_inserted);

      if (observer_inserted)
      {
        o.d = this;
      }
    }

    void pop(observer_data& o) noexcept
    {
      const auto count_erased = [&] {
        std::lock_guard<decltype(mutex)> lock{mutex};
        return observers.erase(&o);
      }();
      assert(count_erased > 0);

      if (count_erased > 0)
      {
        o.p = nullptr;
        o.d = nullptr;
      }
    }

  private:
    // Yes this might be possible to do more efficiently with atomics, but will also be _much_ more
    // error prone.
    std::mutex                         mutex;
    std::unordered_set<observer_data*> observers;
  };
}

template <typename T>
class observer_ptr : private detail::observer_data
{
public:
  class observable_deleter final : public detail::observable_deleter_base
  {
  public:
    void operator()(T* p) noexcept(noexcept(delete p))
    {
      static_assert(!std::is_void<T>::value, "can't delete pointer to incomplete type");
      static_assert(sizeof(T) > 0, "can't delete pointer to incomplete type");

      wipe();
      delete p;
    }
  };

  constexpr observer_ptr() noexcept = default;
  constexpr observer_ptr(std::nullptr_t) noexcept
  {
  }

  /// Convert from compatible unique_ptr
  template <typename U,
            typename = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
  observer_ptr(std::unique_ptr<U, typename observer_ptr<U>::observable_deleter>& rhs) noexcept
  {
    if (rhs)
    {
      this->p = static_cast<T*>(rhs.get());
      rhs.get_deleter().push(*this);
    }
  }

  observer_ptr(const observer_ptr& rhs) noexcept
  {
    if (rhs)
    {
      this->p = static_cast<T*>(rhs.get());
      rhs.d->push(*this);
    }
  }

  template <typename U,
            typename = typename std::enable_if<std::is_convertible<U*, T*>::value
                                               && !std::is_same<U, T>::value>::type>
  observer_ptr(const observer_ptr<U>& rhs) noexcept
  {
    if (rhs)
    {
      this->p = static_cast<T*>(rhs.get());
      rhs.d->push(*this);
    }
  }

  template <typename U>
  observer_ptr(const observer_ptr<U>& rhs, T* const rp) noexcept
  {
    assert(rp != nullptr);
    assert(rhs.d != nullptr);

    this->p = rp;
    rhs.d->push(*this);
  }

  observer_ptr& operator=(const observer_ptr& rhs) noexcept
  {
    if (this->p == rhs.p)
      return *this;

    reset();
    if (rhs)
    {
      this->p = static_cast<T*>(rhs.get());
      rhs.d->push(*this);
    }

    return *this;
  }

  ~observer_ptr() noexcept
  {
    reset();
  }

  void reset()
  {
    if (d)
    {
      d->pop(*this);
    }
  }

  constexpr T* get() const noexcept
  {
    return static_cast<T*>(this->p);
  }

  constexpr explicit operator bool() const
  {
    return this->p != nullptr;
  }

  constexpr T& operator*() const noexcept
  {
    assert(this->p != nullptr);
    return *get();
  }

  constexpr T* operator->() const noexcept
  {
    assert(this->p != nullptr);
    return get();
  }

private:
  template <typename>
  friend class observer_ptr;
};

template <typename T>
using observable_ptr = std::unique_ptr<T, typename observer_ptr<T>::observable_deleter>;

template <typename T, typename... Args>
observable_ptr<T> make_observable(Args&&... args)
{
  return observable_ptr<T>{new T(std::forward<Args>(args)...)};
}

template <typename T, typename TS>
observer_ptr<T> dynamic_pointer_cast(const observer_ptr<TS>& r) noexcept
{
  if (auto* p = dynamic_cast<T*>(r.get()))
    return observer_ptr<T>{r, p};
  return {};
}

template <typename T1, typename T2>
constexpr bool operator==(const observer_ptr<T1>& lhs, const observer_ptr<T2>& rhs) noexcept
{
  return lhs.get() == rhs.get();
}

template <typename T1, typename T2>
constexpr bool operator==(const observer_ptr<T1>& lhs, T2* rhs) noexcept
{
  return lhs.get() == rhs;
}

template <typename T1, typename T2>
constexpr bool operator==(T1* lhs, const observer_ptr<T2>& rhs) noexcept
{
  return lhs == rhs.get();
}

template <typename T>
constexpr bool operator==(const observer_ptr<T>& lhs, std::nullptr_t) noexcept
{
  return !lhs;
}

template <typename T>
constexpr bool operator==(std::nullptr_t, const observer_ptr<T>& rhs) noexcept
{
  return !rhs;
}

template <typename T1, typename T2>
constexpr bool operator!=(const observer_ptr<T1>& lhs, const observer_ptr<T2>& rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T1, typename T2>
constexpr bool operator!=(const observer_ptr<T1>& lhs, T2* rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T1, typename T2>
constexpr bool operator!=(T1* lhs, const observer_ptr<T2>& rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T>
constexpr bool operator!=(const observer_ptr<T>& lhs, std::nullptr_t) noexcept
{
  return static_cast<bool>(lhs);
}

template <typename T>
constexpr bool operator!=(std::nullptr_t, const observer_ptr<T>& rhs) noexcept
{
  return static_cast<bool>(rhs);
}

template <typename T1, typename T2>
constexpr bool operator<(const observer_ptr<T1>& lhs, const observer_ptr<T2>& rhs) noexcept
{
  return lhs.get() < rhs.get();
}

template <typename T1, typename T2>
constexpr bool operator<(const observer_ptr<T1>& lhs, T2* rhs) noexcept
{
  return lhs.get() < rhs;
}

template <typename T1, typename T2>
constexpr bool operator<(T1* lhs, const observer_ptr<T2>& rhs) noexcept
{
  return lhs < rhs.get();
}
}

#endif /* INCLUDED_OBSERVER_PTR_HPP */
