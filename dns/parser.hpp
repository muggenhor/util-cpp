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

#ifndef INCLUDED_DNS_PARSER_HPP
#define INCLUDED_DNS_PARSER_HPP

#include "dns.hpp"
#include "expected.hpp"
#include <gsl/span>
#include <iterator>
#include <system_error>
#include <utility>

namespace dns
{
  enum class parser_error
  {
    // zero is reserved as not-error for use with std::error_code
    no_error = 0,

    not_enough_data,
    invalid_domain_label_type,
    too_many_domain_label_pointers,
    invalid_bitmap_window_size,
    invalid_data_size,
    multiple_opt_records,
  };

  const std::error_category& parser_category() noexcept;

  inline std::error_code make_error_code(parser_error e) noexcept
  {
    return std::error_code(static_cast<int>(e), parser_category());
  }
}

namespace std
{
  template <>
  struct is_error_code_enum<::dns::parser_error> : public true_type {};
}

namespace dns
{
  expected<message> parse(gsl::span<const std::uint8_t> frame);

  inline expected<std::pair<message, const std::uint8_t*>>
    parse(const std::uint8_t* const first, const std::uint8_t* const last)
  {
    using ::util::unexpected;

    if (std::distance(first, last) < 2)
      return unexpected(parser_error::not_enough_data);
    const auto len = static_cast<std::uint16_t>(*first << 8U | (*std::next(first) & 0xffU));
    if (std::distance(first, last) < 2 + len)
      return unexpected(parser_error::not_enough_data);
    const auto next = std::next(first, 2 + len);
    return parse(gsl::span{std::next(first, 2), next})
      .map(
        [next] (auto&& msg) {
          return std::make_pair(std::forward<decltype(msg)>(msg), next);
        });
  }
}

#endif /* INCLUDED_DNS_PARSER_HPP */
