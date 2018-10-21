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

#ifndef INCLUDED_DNS_SERIALIZER_HPP
#define INCLUDED_DNS_SERIALIZER_HPP

#include "dns.hpp"
#include "expected.hpp"
#include <gsl/span>
#include <system_error>

namespace dns
{
  enum class serializer_error
  {
    // zero is reserved as not-error for use with std::error_code
    no_error = 0,

    too_long_domain_name_label,
    too_much_data,
  };

  const std::error_category& serializer_category() noexcept;

  inline std::error_code make_error_code(serializer_error e) noexcept
  {
    return std::error_code(static_cast<int>(e), serializer_category());
  }

  expected<std::vector<std::uint8_t>> serialize(const message& msg);
  expected<gsl::span<std::uint8_t>> serialize(const message& msg, gsl::span<std::uint8_t> buf);

  expected<name> make_name(const std::string_view domainname);
  expected<message> make_question(std::string_view name, rr_type rdtype, rr_class rdclass = rr_class::IN);
}

namespace std
{
  template <>
  struct is_error_code_enum<::dns::serializer_error> : public true_type {};
}

#endif /* INCLUDED_DNS_SERIALIZER_HPP */
