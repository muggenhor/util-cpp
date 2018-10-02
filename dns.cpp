#include <cassert>
#include <climits>
#include <cstddef>
#include <ostream>
#include <optional>
#include <system_error>
#include "dns.hpp"
#include "monads.hpp"

namespace dns
{
  const std::error_category& rcode_category() noexcept
  {
    struct dns_error_category final : public std::error_category
    {
      const char* name() const noexcept override { return "dns"; }

      std::string message(int i) const override
      {
        switch (static_cast<dns::rcode>(i))
        {
          case rcode::no_error:
            return "no error";;
          case rcode::format_error:
            return "format error";
          case rcode::server_failure:
            return "server failure";
          case rcode::name_error:
            return "no such name exists";
          case rcode::not_implemented:
            return "not implemented";
          case rcode::refused:
            return "refused";
          case rcode::yxdomain:
            return "name exists when it shouldn't";
          case rcode::yxrrset:
            return "rrset exists when it shouldn't";
          case rcode::nxrrset:
            return "no such rrset exists";
          case rcode::notauth:
            return "server not authoritative for specified zone";
          case rcode::notzone:
            return "a specified name is outside of the specified zone";
        }

        char msg[64];
        snprintf(msg, sizeof(msg), "unknown %s error: %d", this->name(), i);
        return std::string(msg);
      }

      std::error_condition default_error_condition(int i) const noexcept override
      {
        switch (static_cast<dns::rcode>(i))
        {
          case rcode::no_error:
            return {i, *this};
          case rcode::format_error:
            break;
          case rcode::server_failure:
            break;
          case rcode::name_error:
            break;
          case rcode::not_implemented:
            return std::errc::function_not_supported;
          case rcode::refused:
            return std::errc::operation_not_permitted;
          case rcode::yxdomain:
            break;
          case rcode::yxrrset:
            break;
          case rcode::nxrrset:
            break;
          case rcode::notauth:
            break;
          case rcode::notzone:
            break;
        }

        return {i, *this};
      }
    };
    static const dns_error_category instance;

    return instance;
  }

  const std::error_category& parser_category() noexcept
  {
    struct parser_error_category final : public std::error_category
    {
      const char* name() const noexcept override { return "dns-parser"; }

      std::string message(int i) const override
      {
        switch (static_cast<dns::parser_error>(i))
        {
          case parser_error::no_error:
            return "no error";;
          case parser_error::not_enough_data:
            return "not enought data";
          case parser_error::invalid_domain_label_type:
            return "rejected or unsupported label type in domain name";
          case parser_error::too_many_domain_label_pointers:
            return "limit of label pointers to follow in domain name exceeded";
          case parser_error::invalid_bitmap_window_size:
            return "window size of type bitmap outside of valid range";
          case parser_error::invalid_data_size:
            return "size of data section different than required";
          case parser_error::multiple_opt_records:
            return "more than the maximum of 1 OPT record in message";
        }

        char msg[64];
        snprintf(msg, sizeof(msg), "unknown %s error: %d", this->name(), i);
        return std::string(msg);
      }

      std::error_condition default_error_condition(int i) const noexcept override
      {
        switch (static_cast<dns::parser_error>(i))
        {
          case parser_error::no_error:
            return {i, *this};
          case parser_error::not_enough_data:
            return std::errc::no_message_available;
          case parser_error::invalid_domain_label_type:
            return std::errc::protocol_error;
          case parser_error::too_many_domain_label_pointers:
            return std::errc::too_many_links;
          case parser_error::invalid_bitmap_window_size:
            return std::errc::protocol_error;
          case parser_error::invalid_data_size:
            return std::errc::protocol_error;
          case parser_error::multiple_opt_records:
            return std::errc::protocol_error;
        }

        return {i, *this};
      }
    };
    static const parser_error_category instance;

    return instance;
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  std::ostream& operator<<(std::ostream& os, msgopcode o)
  {
    switch (o)
    {
      case msgopcode::query:          return os << "QUERY";
      case msgopcode::inverse_query:  return os << "IQUERY";
      case msgopcode::status_request: return os << "STATUS";
      case msgopcode::notify:         return os << "NOTIFY";
      case msgopcode::update:         return os << "UPDATE";
    }

    return os << "(unknown:" << static_cast<unsigned>(o) << ')';
  }

  std::ostream& operator<<(std::ostream& os, rr_type r)
  {
    switch (r)
    {
      case rr_type::MD:         return os << "MD";
      case rr_type::MF:         return os << "MF";
      case rr_type::MB:         return os << "MB";
      case rr_type::MG:         return os << "MG";
      case rr_type::MR:         return os << "MR";
      case rr_type::MINFO:      return os << "MINFO";
      case rr_type::WKS:        return os << "WKS";
      case rr_type::A:          return os << "A";
      case rr_type::NS:         return os << "NS";
      case rr_type::CNAME:      return os << "CNAME";
      case rr_type::SOA:        return os << "SOA";
      case rr_type::NULL_:      return os << "NULL_";
      case rr_type::PTR:        return os << "PTR";
      case rr_type::HINFO:      return os << "HINFO";
      case rr_type::MX:         return os << "MX";
      case rr_type::TXT:        return os << "TXT";
      case rr_type::OPT:        return os << "OPT";
      case rr_type::RP:         return os << "RP";
      case rr_type::AFSDB:      return os << "AFSDB";
      case rr_type::X25:        return os << "X25";
      case rr_type::ISDN:       return os << "ISDN";
      case rr_type::RT:         return os << "RT";
      case rr_type::NSAP:       return os << "NSAP";
      case rr_type::NSAP_PTR:   return os << "NSAP-PTR";
      case rr_type::PX:         return os << "PX";
      case rr_type::GPOS:       return os << "GPOS";
      case rr_type::SIG:        return os << "SIG";
      case rr_type::KEY:        return os << "KEY";
      case rr_type::NXT:        return os << "NXT";
      case rr_type::AAAA:       return os << "AAAA";
      case rr_type::LOC:        return os << "LOC";
      case rr_type::EID:        return os << "DID";
      case rr_type::NIMLOC:     return os << "NIMLOC";
      case rr_type::SRV:        return os << "SRV";
      case rr_type::ATMA:       return os << "ATMA";
      case rr_type::NAPTR:      return os << "NAPTR";
      case rr_type::KX:         return os << "KX";
      case rr_type::CERT:       return os << "CERT";
      case rr_type::A6:         return os << "A6";
      case rr_type::DNAME:      return os << "DNAME";
      case rr_type::SINK:       return os << "SINK";
      case rr_type::APL:        return os << "APL";
      case rr_type::DS:         return os << "DS";
      case rr_type::RRSIG:      return os << "RRSIG";
      case rr_type::NSEC:       return os << "NSEC";
      case rr_type::DNSKEY:     return os << "DNSKEY";
      case rr_type::SSHFP:      return os << "SSHFP";
      case rr_type::IPSECKEY:   return os << "IPSECKEY";
      case rr_type::DHCID:      return os << "DHCID";
      case rr_type::NSEC3:      return os << "NSEC3";
      case rr_type::NSEC3PARAM: return os << "NSEC3PARAM";
      case rr_type::SMIMEA:     return os << "SMIMEA";
      case rr_type::TLSA:       return os << "TLSA";
      case rr_type::HIP:        return os << "HIP";
      case rr_type::CDS:        return os << "CDS";
      case rr_type::CDNSKEY:    return os << "CDNSKEY";
      case rr_type::OPENPGPKEY: return os << "OPENPGPKEY";
      case rr_type::CSYNC:      return os << "CSYNC";
      case rr_type::SPF:        return os << "SPF";
      case rr_type::EUI48:      return os << "EUI48";
      case rr_type::EUI64:      return os << "EUI64";
      case rr_type::TKEY:       return os << "TKEY";
      case rr_type::TSIG:       return os << "TSIG";
      case rr_type::URI:        return os << "URI";
      case rr_type::CAA:        return os << "CAA";
      case rr_type::TA:         return os << "TA";
      case rr_type::DLV:        return os << "DLV";
      case rr_type::MAILB:      return os << "MAILB";
      case rr_type::MAILA:      return os << "MAILA";
      case rr_type::IXFR:       return os << "IXFR";
      case rr_type::AXFR:       return os << "AXFR";
      case rr_type::ANY:        return os << "*";
    }

    return os << "(unknown:" << static_cast<unsigned>(r) << ')';
  }

  std::ostream& operator<<(std::ostream& os, rr_class r)
  {
    switch (r)
    {
      case rr_class::IN:    return os << "IN";
      case rr_class::CS:    return os << "CS";
      case rr_class::CH:    return os << "CH";
      case rr_class::HS:    return os << "HS";
      case rr_class::NONE:  return os << "NONE";
      case rr_class::ANY:   return os << "*";
    }

    return os << "(unknown:" << static_cast<unsigned>(r) << ')';
  }

  std::ostream& operator<<(std::ostream& os, option_code o)
  {
    switch (o)
    {
      case option_code::LLQ:                return os << "LLQ";
      case option_code::UL:                 return os << "UL";
      case option_code::NSID:               return os << "NSID";
      case option_code::DAU:                return os << "DAU";
      case option_code::DHU:                return os << "DHU";
      case option_code::N3U:                return os << "N3U";
      case option_code::edns_client_subnet: return os << "edns_client_subnet";
      case option_code::EDNS_EXPIRE:        return os << "EDNS_EXPIRE";
      case option_code::COOKIE:             return os << "COOKIE";
      case option_code::edns_tcp_keepalive: return os << "edns_tcp_keepalive";
      case option_code::padding:            return os << "padding";
      case option_code::CHAIN:              return os << "CHAIN";
      case option_code::edns_key_tag:       return os << "edns_key_tag";
      case option_code::device_id:          return os << "device_id";
    }

    return os << "(unknown:" << static_cast<unsigned>(o) << ')';
  }

  std::ostream& operator<<(std::ostream& os, digest_algorithm algo)
  {
    switch (algo)
    {
      case digest_algorithm::SHA1:      return os << "SHA-1";
      case digest_algorithm::SHA256:    return os << "SHA-256";
      case digest_algorithm::SHA384:    return os << "SHA-384";
      case digest_algorithm::ECC_GOST:  return os << "ECC-GOST";
    }

    return os << "(unknown:" << static_cast<unsigned>(algo) << ')';
  }

  std::ostream& operator<<(std::ostream& os, security_algorithm algo)
  {
    switch (algo)
    {
      case security_algorithm::DELETE:              return os << "DELETE";
      case security_algorithm::RSAMD5:              return os << "RSAMD5";
      case security_algorithm::DH:                  return os << "DH";
      case security_algorithm::DSA:                 return os << "DSA";
      case security_algorithm::RSASHA1:             return os << "RSASHA1";
      case security_algorithm::DSA_NSEC3_SHA1:      return os << "DSA-NSEC3-SHA1";
      case security_algorithm::RSASHA1_NSEC3_SHA1:  return os << "RSASHA1-NSEC3-SHA1";
      case security_algorithm::RSASHA256:           return os << "RSASHA256";
      case security_algorithm::RSASHA512:           return os << "RSASHA512";
      case security_algorithm::ECC_GOST:            return os << "ECC-GOST";
      case security_algorithm::ECDSAP256SHA256:     return os << "ECDSAP256SHA256";
      case security_algorithm::ECDSAP384SHA384:     return os << "ECDSAP384SHA384";
      case security_algorithm::ED25519:             return os << "ED25519";
      case security_algorithm::ED448:               return os << "ED448";
    }

    return os << "(unknown:" << static_cast<unsigned>(algo) << ')';
  }
#pragma GCC diagnostic pop

  namespace
  {
    using util::unexpected;

    expected<std::uint8_t>
      consume_u8(gsl::span<const std::uint8_t>& input) noexcept
    {
      if (input.size() < 1)
        return unexpected(parser_error::not_enough_data);
      auto r = input[0];
      input = input.subspan<1>();
      return r;
    }

    expected<std::uint16_t>
      consume_u16(gsl::span<const std::uint8_t>& input) noexcept
    {
      if (input.size() < 2)
        return unexpected(parser_error::not_enough_data);
      auto r = static_cast<std::uint16_t>(
          static_cast<std::uint16_t>(input[0]) << 8 | input[1]);
      input = input.subspan<2>();
      return r;
    }

    expected<std::uint32_t>
      consume_u32(gsl::span<const std::uint8_t>& input) noexcept
    {
      if (input.size() < 4)
        return unexpected(parser_error::not_enough_data);
      auto r = static_cast<std::uint32_t>(
          static_cast<std::uint32_t>(input[0]) << 24 | input[1] << 16 | input[2] << 8 | input[3]);
      input = input.subspan<4>();
      return r;
    }

    expected<gsl::span<const std::uint8_t>>
    subspan(gsl::span<const std::uint8_t> span, std::ptrdiff_t offset, std::ptrdiff_t count = -1) noexcept
    {
      assert(offset >= 0);
      if (span.size() < offset
       || (count >= 0 && span.size() - offset < count))
        return unexpected(parser_error::not_enough_data);

      if (count < 0)
        return span.subspan(offset);
      else
        return span.subspan(offset, count);
    }

    expected<gsl::span<const std::uint8_t>>
    consume_subspan(gsl::span<const std::uint8_t>& span, const std::ptrdiff_t count = -1) noexcept
    {
      auto r = subspan(span, 0, count);
      if (r)
      {
        if (count < 0)
          span = {};
        else
          span = span.subspan(count);
      }
      return r;
    }

    expected<gsl::span<const std::uint8_t>>
    consume_u8varsubspan(gsl::span<const std::uint8_t>& span) noexcept
    {
      return consume_u8(span)
        .map([&] (const auto length) {
          return consume_subspan(span, length);
        });
    }

    expected<gsl::span<const std::uint8_t>>
    consume_u16varsubspan(gsl::span<const std::uint8_t>& span) noexcept
    {
      return consume_u16(span)
        .map([&] (const auto length) {
          return consume_subspan(span, length);
        });
    }

    enum class label_type_mask
    {
      // RFC 1035
      normal                                            = 0b0001,
      compression_pointer                               = 0b0010,
      // RFC 2673
      extended [[deprecated("Obsoleted by RFC 6891")]]  = 0b0100,
      unallocated                                       = 0b1000,
    };
    constexpr int operator|(label_type_mask lhs, int rhs) noexcept
    {
      return static_cast<int>(lhs) | rhs;
    }
    constexpr int operator|(label_type_mask lhs, label_type_mask rhs) noexcept
    {
      return lhs | static_cast<int>(rhs);
    }
    constexpr int operator|(int lhs, label_type_mask rhs) noexcept
    {
      return rhs | lhs;
    }
    constexpr int operator&(label_type_mask lhs, int rhs) noexcept
    {
      return static_cast<int>(lhs) | rhs;
    }
    constexpr int operator&(int lhs, label_type_mask rhs) noexcept
    {
      return rhs | lhs;
    }

    expected<std::pair<std::vector<std::string_view>, gsl::span<const std::uint8_t> /* unused remainder of name_frame */>>
      parse_domain_name(
            const gsl::span<const std::uint8_t> frame
          , gsl::span<const std::uint8_t> name_frame
          , int labels_to_accept = label_type_mask::normal | label_type_mask::compression_pointer
        ) noexcept
    {
      const auto max_follow_count = std::min(static_cast<unsigned>(frame.size() / 4), 255U);
      unsigned pointer_labels_followed = 0;
      std::vector<std::string_view> labels;
      //const auto label = std::regex("^[A-Za-z](?:[-A-Za-z0-9]{0,61}[A-Za-z0-9])?$");
      bool name_is_compressed = false;
      auto pos = name_frame;
      for (;;)
      {
        const auto label_size = consume_u8(pos);
        if (label_size && *label_size <= 0)
          break;
        const auto label_type = label_size.map([&](std::uint8_t label_size) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            switch (static_cast<std::uint8_t>(label_size & 0b1100'0000))
            {
              case 0b1100'0000:
                return label_type_mask::compression_pointer;
              case 0b0000'0000:
                return label_type_mask::normal;
              case 0b0100'0000:
                return label_type_mask::extended;
              case 0b1000'0000:
              default: // shut-up GCC which fails to detect that these bit values cover all possibilities
                return label_type_mask::unallocated;
            }
#pragma GCC diagnostic pop
          });

        if (!label_type)
          return unexpected(std::move(label_type).error());
        if (!(*label_type & labels_to_accept))
          return unexpected(parser_error::invalid_domain_label_type);

        switch (*label_type)
        {
          // Handle name pointers, which terminate a sequence of labels
          case label_type_mask::compression_pointer:
          {
            // prevent infinite loops
            if (++pointer_labels_followed > max_follow_count)
              return unexpected(parser_error::too_many_domain_label_pointers);

            const auto offset = consume_u8(pos).map([&](std::uint8_t lsb) {
                return static_cast<std::uint16_t>((*label_size & 0x3f) << 8 | lsb);
              });
            if (!name_is_compressed)
            {
              name_frame = pos;
              name_is_compressed = true;
            }
            if (auto new_pos = offset.map([&] (const auto offset) {
                  return subspan(frame, offset);
                }))
              pos = *new_pos;
            else
              return unexpected(std::move(new_pos).error());
            break;
          }
          case label_type_mask::normal:
          {
            if (const auto label = consume_subspan(pos, *label_size))
              labels.emplace_back(reinterpret_cast<const char*>(label->data()), label->size());
            else
              return unexpected(std::move(label).error());
            break;
          }
          default:
            return unexpected(parser_error::invalid_domain_label_type);
        }
      }
      if (!name_is_compressed)
        name_frame = pos;

      return std::make_pair(std::move(labels), name_frame);
    }

    expected<std::vector<std::string_view>>
      consume_domain_name(
            const gsl::span<const std::uint8_t> frame
          , gsl::span<const std::uint8_t>& input
          , int labels_to_accept = label_type_mask::normal | label_type_mask::compression_pointer
        ) noexcept
    {
      auto r = parse_domain_name(frame, input, labels_to_accept);
      if (!r)
        return unexpected(std::move(r).error());
      input = r->second;
      return std::move(r->first);
    }

    /// Parses according to RFC 4034 section 4.1.2: The Type Bit Maps Field
    /// \post on success all of input will have been consumed
    expected<std::set<rr_type>>
      parse_type_bit_map(gsl::span<const std::uint8_t> input) noexcept
    {
      expected<std::set<rr_type>> types(std::in_place);
      do
      {
        const auto window = consume_u8(input);
        const auto bitmap = consume_u8varsubspan(input);
        if (!window || !bitmap || bitmap->empty() || bitmap->size() > 32)
        {
          return unexpected(monad::get_error(
                window, bitmap, parser_error::invalid_bitmap_window_size));
        }

        unsigned idx = 0U;
        for (const unsigned octet : *bitmap)
        {
          const unsigned offset = idx++;
          for (unsigned bit = 0; bit < 8; ++bit)
          {
            if (octet & (1U << (7 - bit)))
            {
              types->emplace(static_cast<rr_type>(*window | (offset * 8U + bit)));
            }
          }
        }
      } while (types && !input.empty());
      return types;
    }

    expected<decltype(rr::rdata)> parse_rdata(
        const dns::rcode rcode, const rr_type type, const rr_class rdclass, const std::chrono::duration<std::uint32_t> ttl,
        const gsl::span<const std::uint8_t> frame, gsl::span<const std::uint8_t> rdata_frame)
    {
      switch (type)
      {
        case rr_type::CNAME:
        case rr_type::PTR:
        case rr_type::NS:
         // deprecated records
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        case rr_type::MD:
        case rr_type::MF:
        case rr_type::MG:
        case rr_type::MR:
#pragma GCC diagnostic pop
          return consume_domain_name(frame, rdata_frame);
        case rr_type::MX:
        {
          const auto preference = consume_u16(rdata_frame);
          auto       name       = consume_domain_name(frame, rdata_frame);
          return monad::construct<mx_rdata>(preference, std::move(name));
        }
        case rr_type::SOA:
        {
          auto       authority    = consume_domain_name(frame, rdata_frame);
          auto       hostmaster   = consume_domain_name(frame, rdata_frame);
          const auto serial       = consume_u32(rdata_frame);
          const auto refresh      = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          const auto retry        = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          const auto expiry       = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          const auto negative_ttl = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          return monad::construct<soa_rdata>(
              std::move(authority), std::move(hostmaster), serial, refresh, retry, expiry, negative_ttl);
        }
        case rr_type::TXT:
        {
          txt_rdata txt;
          do
          {
            if (const auto string = consume_u8varsubspan(rdata_frame))
              txt.strings.emplace_back(reinterpret_cast<const char*>(string->data()), string->size());
            else
              return unexpected(std::move(string).error());
          } while (!rdata_frame.empty());
          return std::move(txt);
        }
        case rr_type::DS:
        case rr_type::CDS:
        {
          const auto key_tag     = consume_u16(rdata_frame);
          const auto algorithm   = monad::construct<security_algorithm>(consume_u8(rdata_frame));
          const auto digest_type = monad::construct<digest_algorithm>(consume_u8(rdata_frame));
          const auto digest_size = digest_type.map([] (const auto type) {
              switch (type)
              {
                case digest_algorithm::SHA1:
                  return 160 / 8;
                case digest_algorithm::SHA256:
                  return 256 / 8;
                case digest_algorithm::SHA384:
                  return 384 / 8;
                case digest_algorithm::ECC_GOST:
                  break;
              }
              return -1;
            });
          const auto digest = digest_size.map(
              [&](const auto digest_size) -> expected<gsl::span<const std::uint8_t>> {
              if (digest_size >= 0
               && rdata_frame.size() > digest_size)
                return unexpected(parser_error::invalid_data_size);
              return consume_subspan(rdata_frame, digest_size);
            });
          return monad::construct<ds_rdata>(key_tag, algorithm, digest_type, digest);
        }
        case rr_type::DNSKEY:
        case rr_type::CDNSKEY:
        {
          const auto flags     = consume_u16(rdata_frame);
          const auto protocol  = consume_u8(rdata_frame);
          const auto algorithm = monad::construct<security_algorithm>(consume_u8(rdata_frame));
          return monad::construct<dnskey_rdata>(flags, protocol, algorithm, consume_subspan(rdata_frame));
        }
        case rr_type::RRSIG:
        {
          const auto covered_type = monad::construct<rr_type>(consume_u16(rdata_frame));
          const auto algorithm    = monad::construct<security_algorithm>(consume_u8(rdata_frame));
          const auto label_count  = consume_u8(rdata_frame);
          const auto original_ttl = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          const auto expiration   = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          const auto inception    = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rdata_frame));
          const auto key_tag      = consume_u16(rdata_frame);
          const auto signer_name  = consume_domain_name(frame, rdata_frame, 0|label_type_mask::normal);
          return monad::construct<rrsig_rdata>(
              covered_type, algorithm, label_count, original_ttl, expiration,
              inception, key_tag, std::move(signer_name), consume_subspan(rdata_frame));
        }
        case rr_type::NSEC:
        {
          auto next_domain_name = consume_domain_name(frame, rdata_frame, 0|label_type_mask::normal);
          auto types            = parse_type_bit_map(rdata_frame);
          return monad::construct<nsec_rdata>(std::move(next_domain_name), std::move(types));
        }
        case rr_type::NSEC3:
        {
          const auto hash_algo        = monad::construct<digest_algorithm>(consume_u8(rdata_frame));
          const auto opt_out          = consume_u8(rdata_frame).map([] (const auto flags) -> bool { return flags & 0x1; });
          const auto iterations       = consume_u16(rdata_frame);
          const auto salt             = consume_u8varsubspan(rdata_frame);
          const auto next_hashed_name = consume_u8varsubspan(rdata_frame);
                auto types            = parse_type_bit_map(rdata_frame);
          return monad::construct<nsec3_rdata>(
              hash_algo, opt_out, iterations, salt, next_hashed_name, std::move(types));
        }
        case rr_type::A:
        {
          if (rdata_frame.size() != decltype(a_rdata::addr)::extent)
            return unexpected(parser_error::invalid_data_size);
          return a_rdata{rdata_frame};
        }
        case rr_type::AAAA:
        {
          if (rdata_frame.size() != decltype(aaaa_rdata::addr)::extent)
            return unexpected(parser_error::invalid_data_size);
          return aaaa_rdata{rdata_frame};
        }
        case rr_type::OPT:
        {
          const auto udp_payload_size = static_cast<std::uint16_t>(rdclass);
          const auto extended_rcode   = static_cast<dns::rcode>(((ttl.count() >> 20) & 0xff0) | (static_cast<std::uint16_t>(rcode) & 0x0f));
          const auto edns_version     = static_cast<std::uint8_t>(ttl.count() >> 16);
          const auto flags            = static_cast<std::uint16_t>(ttl.count());
          const bool dnssec_ok        = flags & 0b1000'0000'0000'0000;
          edns_options options;
          while (!rdata_frame.empty())
          {
            const auto code  = monad::construct<option_code>(consume_u16(rdata_frame));
            const auto value = consume_u16varsubspan(rdata_frame);
            if (auto err = monad::get_error(code, value))
              return unexpected(std::move(err));
            options.emplace(*code, *value);
          }
          return opt_rdata{
                udp_payload_size
              , extended_rcode
              , edns_version
              , flags
              , dnssec_ok
              , std::move(options)
            };
        }
        default:
          return rdata_frame;
      }
    }

    expected<rr> consume_rr(
        const dns::rcode rcode, const gsl::span<const std::uint8_t> frame, gsl::span<const std::uint8_t>& rr_frame)
    {
      auto       name        = consume_domain_name(frame, rr_frame);
      const auto type        = monad::construct<rr_type>(consume_u16(rr_frame));
      const auto rdclass     = monad::construct<rr_class>(consume_u16(rr_frame));
      const auto ttl         = monad::construct<std::chrono::duration<std::uint32_t>>(consume_u32(rr_frame));
      const auto rdata       = monad::map(parse_rdata, rcode, type, rdclass, ttl, frame, consume_u16varsubspan(rr_frame));

      return monad::construct<rr>(std::move(name), type, rdclass, ttl, std::move(rdata));
    }
  }

  expected<message> parse(const gsl::span<const std::uint8_t> frame)
  {
    static_assert(sizeof(frame[0]) * CHAR_BIT == 8, "This code is written under the assumption of a 8-bit byte");

    auto cur = frame;

    const auto txid  = consume_u16(cur);
    const auto flags = consume_u16(cur);

    const auto question_count   = consume_u16(cur);
    const auto answer_count     = consume_u16(cur);
    const auto authority_count  = consume_u16(cur);
    const auto additional_count = consume_u16(cur);

    if (auto err = monad::get_error(
          txid, flags, question_count, answer_count, authority_count, additional_count))
      return unexpected(std::move(err));

    // RFC 1035 4.1.1
    const bool is_response             = (*flags >> 15) & 0x1;
    const auto opcode                  = static_cast<msgopcode>((*flags >> 11) & 0xf);
    const bool is_authoritative_answer = (*flags >> 10) & 0x1;
    const bool is_truncated            = (*flags >>  9) & 0x1;
    const bool is_recursion_desired    = (*flags >>  8) & 0x1;
    const bool is_recursion_available  = (*flags >>  7) & 0x1;
    auto       rcode                   = static_cast<dns::rcode>((*flags >> 0) & 0xf);

    // RFC 2535 6.1
    const bool authentic_data          = (*flags >>  5) & 0x1;
    const bool checking_disabled       = (*flags >>  4) & 0x1;

    std::vector<question> questions;
    questions.reserve(*question_count);
    for (std::uint16_t i = 0; i < *question_count; ++i)
    {
      auto name    = consume_domain_name(frame, cur);
      auto rdtype  = monad::construct<rr_type>(consume_u16(cur));
      auto rrclass = monad::construct<rr_class>(consume_u16(cur));
      if (auto q = monad::construct<question>(std::move(name), rdtype, rrclass))
        questions.push_back(std::move(*q));
      else
        return unexpected(std::move(q).error());
    }

    std::vector<rr> answers;
    answers.reserve(*answer_count);
    std::vector<rr> authorities;
    authorities.reserve(*authority_count);
    std::vector<rr> additionals;
    additionals.reserve(*additional_count);

    for (std::size_t i = 0; i < static_cast<std::uint16_t>(*answer_count + *authority_count + *additional_count); ++i)
    {
      auto& rrset = i < *answer_count                    ? answers
                  : i < *answer_count + *authority_count ? authorities
                  :                                        additionals
                  ;

      if (auto rr = monad::map(consume_rr, rcode, frame, cur))
        rrset.push_back(std::move(*rr));
      else
        return unexpected(std::move(rr).error());
    }

    std::optional<opt_rdata> edns;
    for (const auto& rr : additionals)
    {
      if (const auto* const opt = std::get_if<opt_rdata>(&rr.rdata))
      {
        if (edns)
          return unexpected(parser_error::multiple_opt_records);

        edns = *opt;
        rcode = edns->extended_rcode;
      }
    }

    if (is_response)
      return reply{*txid, rcode, is_authoritative_answer, is_truncated, is_recursion_available, authentic_data, checking_disabled, std::move(edns), std::move(questions), std::move(answers), std::move(authorities), std::move(additionals)};
    else
      return query{*txid, opcode, is_recursion_desired, authentic_data, checking_disabled, std::move(edns), std::move(questions), std::move(answers), std::move(authorities), std::move(additionals)};
  }
}
