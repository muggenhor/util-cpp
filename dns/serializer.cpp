#include "serializer.hpp"
#include <cassert>
#include <climits>
#include <cstddef>
#include <iterator>
#include <limits>
#include <ostream>
#include <optional>
#include <random>
#include <system_error>
#include "monads.hpp"
#include "overload.hpp"

namespace dns
{
  const std::error_category& serializer_category() noexcept
  {
    struct serializer_error_category final : public std::error_category
    {
      const char* name() const noexcept override { return "dns-serializer"; }

      std::string message(int i) const override
      {
        switch (static_cast<dns::serializer_error>(i))
        {
          case serializer_error::no_error:
            return "no error";;
          case serializer_error::too_long_domain_name_label:
            return "too long domain name label";
          case serializer_error::too_much_data:
            return "to much data";
        }

        char msg[64];
        snprintf(msg, sizeof(msg), "unknown %s error: %d", this->name(), i);
        return std::string(msg);
      }

      std::error_condition default_error_condition(int i) const noexcept override
      {
        switch (static_cast<dns::serializer_error>(i))
        {
          case serializer_error::no_error:
            return {i, *this};
          case serializer_error::too_long_domain_name_label:
            return std::errc::protocol_error;
          case serializer_error::too_much_data:
            return std::errc::value_too_large;
        }

        return {i, *this};
      }
    };
    static const serializer_error_category instance;

    return instance;
  }

  namespace
  {
    using util::unexpected;

    constexpr std::array<std::uint8_t, 1> serialize(std::uint8_t i)
    {
      return {
        i,
      };
    }

    constexpr std::array<std::uint8_t, 2> serialize(std::uint16_t i)
    {
      return {
        static_cast<std::uint8_t>(i >> 8u),
        static_cast<std::uint8_t>(i >> 0u),
      };
    }

    constexpr std::array<std::uint8_t, 4> serialize(std::uint32_t i)
    {
      return {
        static_cast<std::uint8_t>(i >> 24u),
        static_cast<std::uint8_t>(i >> 16u),
        static_cast<std::uint8_t>(i >>  8u),
        static_cast<std::uint8_t>(i >>  0u),
      };
    }

    struct indexed_buf
    {
      const gsl::span<std::uint8_t> buf;
      std::size_t& i;
    };

    template <typename C, typename A>
    std::error_code append(C& o, A&& a)
    {
      using std::begin;
      using std::end;

      if constexpr (std::is_rvalue_reference_v<A&&>)
      {
        o.insert(
              end(o)
            , std::make_move_iterator(begin(a))
            , std::make_move_iterator(end(a))
            );
      }
      else
      {
        o.insert(
              end(o)
            , begin(a)
            , end(a)
            );
      }

      return {};
    }

    template <typename A>
    std::error_code append(indexed_buf o, A&& a)
    {
      using std::begin;
      using std::end;

      const std::size_t size = std::distance(begin(a), end(a));
      if (size > o.buf.size() - o.i)
        return serializer_error::too_much_data;

      if constexpr (std::is_rvalue_reference_v<A&&>)
      {
        std::copy(
              std::make_move_iterator(begin(a))
            , std::make_move_iterator(end(a))
            , &o.buf[o.i]);
      }
      else
      {
        std::copy(begin(a), end(a), &o.buf[o.i]);
      }

      o.i += size;
      return {};
    }

    template <typename OutputRange>
    std::error_code serialize(const message& msg, OutputRange& out)
    {
      append(out, serialize(msg.txid));
      const auto flags = static_cast<std::uint16_t>(
            msg.is_response                                 ? 0b1000000000000000 : 0
          | ((static_cast<std::uint8_t>(msg.opcode) << 11u) & 0b0111100000000000)
          | msg.is_authoritative_answer                     ? 0b0000010000000000 : 0
          | msg.is_truncated                                ? 0b0000001000000000 : 0
          | msg.is_recursion_desired                        ? 0b0000000100000000 : 0
          | msg.is_recursion_desired                        ? 0b0000000010000000 : 0
          | msg.authentic_data                              ? 0b0000000000100000 : 0
          | msg.checking_disabled                           ? 0b0000000000010000 : 0
          | (static_cast<std::uint8_t>(msg.rcode)           & 0b0000000000001111)
          );
      append(out, serialize(flags));
      append(out, serialize(static_cast<std::uint16_t>(msg.questions .size())));
      append(out, serialize(static_cast<std::uint16_t>(msg.answers   .size())));
      append(out, serialize(static_cast<std::uint16_t>(msg.authority .size())));
      if (auto e = append(out, serialize(static_cast<std::uint16_t>(msg.additional.size() + (msg.edns ? 1u : 0u)))))
        return e;

      for (const auto& question : msg.questions)
      {
        for (const auto& label : question.labels)
        {
          if (label.size() > 0x3fu)
            return serializer_error::too_long_domain_name_label;
          append(out, serialize(static_cast<std::uint8_t>(label.size())));
          append(out, label);
        }
        append(out, serialize(static_cast<std::uint8_t>(0)));
        append(out, serialize(static_cast<std::uint16_t>(question.rdtype)));
        if (auto e = append(out, serialize(static_cast<std::uint16_t>(question.rdclass))))
          return e;
      }

      if (!msg.answers.empty()
       || !msg.authority.empty()
       || !msg.additional.empty())
        return make_error_code(std::errc::not_supported);

      if (msg.edns)
      {
        // RFC 6891 6.1.2
        // MUST be 0 (root domain)
        append(out, serialize(static_cast<std::uint8_t>(0)));

        append(out, serialize(static_cast<std::uint16_t>(rr_type::OPT)));
        append(out, serialize(msg.edns->udp_payload_size));
        append(out, serialize(static_cast<std::uint8_t>(static_cast<std::uint16_t>(msg.edns->extended_rcode) >> 4)));
        append(out, serialize(msg.edns->edns_version));
        append(out, serialize(static_cast<std::uint16_t>(
                msg.edns->dnssec_ok ? 0b1000'0000'0000'0000 : 0
              | (msg.edns->flags    & 0b0111'1111'1111'1111)
              )));

        std::size_t size = 0;
        for (const auto& [code, data]: msg.edns->options)
        {
          static_cast<void>(code);
          size += 4;
          size += data.size();
        }

        if (size > std::numeric_limits<std::uint16_t>::max())
          return serializer_error::too_much_data;

        if (auto e = append(out, serialize(static_cast<std::uint16_t>(size))))
          return e;
        for (const auto& [code, data]: msg.edns->options)
        {
          append(out, serialize(static_cast<std::uint16_t>(code)));

          if (data.size() > std::numeric_limits<std::uint16_t>::max())
            return serializer_error::too_much_data;
          append(out, serialize(static_cast<std::uint16_t>(data.size())));
          if (auto e = append(out, data))
            return e;
        }
      }

      return {};
    }
  }

  expected<std::vector<std::uint8_t>> serialize(const message& msg)
  {
    std::vector<std::uint8_t> payload;
    if (auto e = serialize(msg, payload))
      return unexpected(e);
    return std::move(payload);
  }

  expected<gsl::span<std::uint8_t>> serialize(const message& msg, gsl::span<std::uint8_t> buf)
  {
    std::size_t i = 0;
    indexed_buf payload{buf, i};
    if (auto e = serialize(msg, payload))
      return unexpected(e);
    return payload.buf.subspan(0, i);
  }

  expected<name> make_name(const std::string_view domainname)
  {
    name labels;
    for (std::size_t label_start = 0u; label_start < domainname.size();)
    {
      const auto label_end = domainname.find('.', label_start);
      const auto label = domainname.substr(label_start, label_end - label_start);
      if (label.size() > 0x3fu)
        return unexpected(serializer_error::too_long_domain_name_label);
      labels.push_back(label);
      if (label_end == std::string_view::npos
       || label_end == domainname.size() - 1)
        break;
      label_start = label_end + 1;
    }

    return labels;
  }

  expected<message> make_question(const std::string_view name, rr_type rdtype, rr_class rdclass)
  {
    question q;
    if (auto labels = make_name(name))
      q.labels = std::move(*labels);
    else
      return unexpected(labels.error());
    q.rdtype  = rdtype;
    q.rdclass = rdclass;

    opt_rdata edns;
    edns.udp_payload_size = 4096;
    edns.extended_rcode   = dns::rcode::no_error;
    edns.edns_version     = 0;
    edns.dnssec_ok        = true;

    std::random_device rnd;
    return monad::construct<message>(
          static_cast<std::uint16_t>(rnd())
        , false
        , msgopcode::query
        , rcode::no_error
        , false
        , false
        , /* is_recursion_desired =*/ true
        , false
        , /* authentic_data =*/ true
        , false
        , std::move(edns)
        , std::vector<question>(1, std::move(q))
        , std::vector<rr>()
        , std::vector<rr>()
        , std::vector<rr>()
        );
  }
}
