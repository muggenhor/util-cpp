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

#ifndef INCLUDED_OVERLOAD_HPP
#define INCLUDED_OVERLOAD_HPP

#include <utility>

namespace util
{
  template <typename... Fs>
  struct visitor : Fs...
  {
    using Fs::operator()...;
  };

  template <typename... Fs>
  visitor(Fs...) -> visitor<Fs...>;

  // TODO: make something like this usable with boost::variant on C++11
  template <typename... Fs>
  auto overload(Fs&&... fs) noexcept(noexcept(visitor{std::forward<Fs>(fs)...}))
  {
    return visitor{std::forward<Fs>(fs)...};
  }
}

#endif /* INCLUDED_OVERLOAD_HPP */
