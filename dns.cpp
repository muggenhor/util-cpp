#include <climits>
#include <cstddef>
#include <ostream>
#include <optional>
#include <system_error>
#include "dns.hpp"

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

    std::optional<std::pair<std::vector<std::string_view>, gsl::span<const std::uint8_t> /* unused remainder of name_frame */>>
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
        if (pos.empty())
          return std::nullopt;

        const auto label_size = pos[0];
        pos = pos.subspan(1);
        if (label_size <= 0)
          break;
        const auto label_type = [&] {
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
          }();

        if (!(label_type & labels_to_accept))
          return std::nullopt;

        switch (label_type)
        {
          // Handle name pointers, which terminate a sequence of labels
          case label_type_mask::compression_pointer:
          {
            if (pos.empty())
              return std::nullopt;
            // prevent infinite loops
            if (++pointer_labels_followed > max_follow_count)
              return std::nullopt;

            const auto offset = (static_cast<std::uint16_t>(label_size & 0x3fU) << 8U)
                              | ((pos[0] & 0xffU) << 0U)
                              ;
            pos = pos.subspan(1);
            if (!name_is_compressed)
            {
              name_frame = pos;
              name_is_compressed = true;
            }
            if (offset >= frame.size())
              return std::nullopt;
            pos = frame.subspan(offset);
            break;
          }
          case label_type_mask::normal:
          {
            if (pos.size() < label_size)
              return std::nullopt;

            labels.emplace_back(reinterpret_cast<const char*>(pos.data()), label_size);
            pos = pos.subspan(label_size);
            break;
          }
          default:
            return std::nullopt;
        }
      }
      if (!name_is_compressed)
        name_frame = pos;

      return std::make_pair(std::move(labels), name_frame);
    }

    /// Parses according to RFC 4034 section 4.1.2: The Type Bit Maps Field
    /// \post on success all of input will have been consumed
    std::optional<std::set<rr_type>>
      parse_type_bit_map(gsl::span<const std::uint8_t> input) noexcept
    {
      std::optional<std::set<rr_type>> types(std::in_place);
      do
      {
        if (input.size() < 2)
        {
          types = std::nullopt;
          break;
        }
        const auto window = static_cast<std::uint16_t>(input[0] << 8U);
        const auto bitmap_length = input[1];
        if (bitmap_length < 1 || bitmap_length > 32
         || input.size() < 2 + bitmap_length)
        {
          types = std::nullopt;
          break;
        }
        const auto bitmap = input.subspan(2, bitmap_length);
        input = input.subspan(2 + bitmap_length);
        unsigned idx = 0U;
        for (const unsigned octet : bitmap)
        {
          const unsigned offset = idx++;
          for (unsigned bit = 0; bit < 8; ++bit)
          {
            if (octet & (1U << (7 - bit)))
            {
              types->emplace(static_cast<rr_type>(window | (offset * 8U + bit)));
            }
          }
        }
      } while (types && !input.empty());
      return types;
    }
  }

  std::optional<message> parse(const gsl::span<const std::uint8_t> frame)
  {
    static_assert(sizeof(frame[0]) * CHAR_BIT == 8, "This code is written under the assumption of a 8-bit byte");

    if (frame.size() < 12)
      return std::nullopt;

    const std::uint16_t txid  = static_cast<std::uint16_t>(frame[0]) << 8U | frame[1];
    const std::uint16_t flags = static_cast<std::uint16_t>(frame[2]) << 8U | frame[3];
    // RFC 1035 4.1.1
    const bool is_response             = (flags >> 15U) & 0x1U;
    const msgopcode opcode              {static_cast<std::uint8_t>((flags >> 11U) & 0xfU)};
    const bool is_authoritative_answer = (flags >> 10U) & 0x1U;
    const bool is_truncated            = (flags >>  9U) & 0x1U;
    const bool is_recursion_desired    = (flags >>  8U) & 0x1U;
    const bool is_recursion_available  = (flags >>  7U) & 0x1U;
    dns::rcode rcode                     {(flags >>  0U) & 0xfU};

    // RFC 2535 6.1
    const bool authentic_data          = (flags >>  5U) & 0x1U;
    const bool checking_disabled       = (flags >>  4U) & 0x1U;

    const std::uint16_t question_count   = static_cast<std::uint16_t>(frame[ 4]) << 8U | frame[ 5];
    const std::uint16_t answer_count     = static_cast<std::uint16_t>(frame[ 6]) << 8U | frame[ 7];
    const std::uint16_t authority_count  = static_cast<std::uint16_t>(frame[ 8]) << 8U | frame[ 9];
    const std::uint16_t additional_count = static_cast<std::uint16_t>(frame[10]) << 8U | frame[11];

    auto cur = frame.subspan(12);
    std::vector<question> questions;
    questions.reserve(question_count);
    for (std::uint16_t i = 0; i < question_count; ++i)
    {
      std::vector<std::string_view> labels;
      if (auto name = parse_domain_name(frame, cur); name)
      {
        labels = std::move(name->first);
        cur = name->second;
      }
      else
      {
        return std::nullopt;
      }
      if (cur.size() < 4)
        return std::nullopt;

      question question{
          std::move(labels)
        , rr_type {static_cast<std::uint16_t>(static_cast<std::uint16_t>(cur[0]) << 8U | cur[1])}
        , rr_class{static_cast<std::uint16_t>(static_cast<std::uint16_t>(cur[2]) << 8U | cur[3])}
      };
      questions.push_back(std::move(question));
      cur = cur.subspan<4>();
    }

    std::vector<rr> answers;
    answers.reserve(answer_count);
    std::vector<rr> authorities;
    authorities.reserve(authority_count);
    std::vector<rr> additionals;
    additionals.reserve(additional_count);

    for (std::size_t i = 0; i < static_cast<std::uint16_t>(answer_count + authority_count + additional_count); ++i)
    {
      auto& rrset = i < answer_count                   ? answers
                  : i < answer_count + authority_count ? authorities
                  :                                      additionals
                  ;

      std::vector<std::string_view> labels;
      if (auto name = parse_domain_name(frame, cur); name)
      {
        labels = std::move(name->first);
        cur = name->second;
      }
      else
      {
        return std::nullopt;
      }
      if (cur.size() < 10)
        return std::nullopt;

      const auto rdlength = static_cast<std::uint16_t>(cur[8]) << 8U | cur[9];
      if (cur.size() < 10 + rdlength)
        return std::nullopt;

      const auto type    = static_cast<rr_type>(static_cast<std::uint16_t>(cur[0]) << 8U | cur[1]);
      const auto rdclass = static_cast<rr_class>(static_cast<std::uint16_t>(cur[2]) << 8U | cur[3]);
      const std::chrono::duration<std::uint32_t> ttl{
          static_cast<std::uint32_t>(cur[4] & 0xffU) << 24U
        | static_cast<std::uint32_t>(cur[5] & 0xffU) << 16U
        | static_cast<std::uint32_t>(cur[6] & 0xffU) <<  8U
        | (cur[7] & 0xffU)};

      auto rdata_frame = cur.subspan(10, rdlength);
      decltype(rr::rdata) rdata = rdata_frame;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
      if (type == rr_type::CNAME
       || type == rr_type::PTR
       || type == rr_type::NS
       // deprecated records
       || type == rr_type::MD
       || type == rr_type::MF
       || type == rr_type::MG
       || type == rr_type::MR)
#pragma GCC diagnostic pop
      {
        if (auto name = parse_domain_name(frame, rdata_frame); name)
          rdata = std::move(name->first);
        else
          return std::nullopt;
      }
      else if (type == rr_type::MX)
      {
        if (rdata_frame.size() < 2)
          return std::nullopt;
        const auto preference = static_cast<std::uint16_t>((rdata_frame[0] << 8U) | rdata_frame[1]);
        if (auto exchange = parse_domain_name(frame, rdata_frame.subspan(2)); exchange)
          rdata = mx_rdata{preference, std::move(exchange->first)};
        else
          return std::nullopt;
      }
      else if (type == rr_type::SOA)
      {
        auto authority  = parse_domain_name(frame, rdata_frame);
        auto hostmaster = authority ? parse_domain_name(frame, authority->second) : authority;
        if (!authority || !hostmaster)
          return std::nullopt;
        rdata_frame = hostmaster->second;
        if (rdata_frame.size() < 20)
          return std::nullopt;
        const auto serial = static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 0] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 1] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[ 2] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[ 3] & 0xffU) <<  0U
            );
        const std::chrono::duration<std::uint32_t> refresh(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 4] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 5] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[ 6] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[ 7] & 0xffU) <<  0U
          ));
        const std::chrono::duration<std::uint32_t> retry(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 8] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 9] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[10] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[11] & 0xffU) <<  0U
          ));
        const std::chrono::duration<std::uint32_t> expiry(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[12] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[13] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[14] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[15] & 0xffU) <<  0U
          ));
        const std::chrono::duration<std::uint32_t> negative_ttl(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[16] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[17] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[18] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[19] & 0xffU) <<  0U
          ));
        rdata = soa_rdata{std::move(authority->first), std::move(hostmaster->first), serial, refresh, retry, expiry, negative_ttl};
      }
      else if (type == rr_type::TXT)
      {
        txt_rdata txt;
        do
        {
          if (rdata_frame.size() < 1)
            return std::nullopt;
          const auto string_size = rdata_frame[0];
          rdata_frame = rdata_frame.subspan(1);
          if (rdata_frame.size() < string_size)
            return std::nullopt;
          txt.strings.emplace_back(reinterpret_cast<const char*>(rdata_frame.data()), string_size);
          rdata_frame = rdata_frame.subspan(string_size);
        } while (!rdata_frame.empty());
        rdata = std::move(txt);
      }
      else if (type == rr_type::DS
            || type == rr_type::CDS)
      {
        if (rdata_frame.size() < 4)
          return std::nullopt;
        ds_rdata ds;
        ds.key_tag = static_cast<std::uint16_t>(
              static_cast<std::uint16_t>(rdata_frame[0] & 0xffU) <<  8U
            | static_cast<std::uint16_t>(rdata_frame[1] & 0xffU) <<  0U
            );
        ds.algorithm   = static_cast<security_algorithm>(rdata_frame[2]);
        ds.digest_type = static_cast<digest_algorithm>(rdata_frame[3]);
        rdata_frame = rdata_frame.subspan(4);
        ds.digest = rdata_frame;
        switch (ds.digest_type)
        {
          case digest_algorithm::SHA1:
            if (ds.digest.size() != 160 / 8)
              return std::nullopt;
            break;
          case digest_algorithm::SHA256:
            if (ds.digest.size() != 256 / 8)
              return std::nullopt;
            break;
          case digest_algorithm::SHA384:
            if (ds.digest.size() != 384 / 8)
              return std::nullopt;
            break;
          case digest_algorithm::ECC_GOST:
            break;
        }
        rdata = std::move(ds);
      }
      else if (type == rr_type::DNSKEY
            || type == rr_type::CDNSKEY)
      {
        if (rdata_frame.size() < 4)
          return std::nullopt;
        dnskey_rdata dnskey;
        dnskey.flags = static_cast<std::uint16_t>(
              static_cast<std::uint16_t>(rdata_frame[0] & 0xffU) <<  8U
            | static_cast<std::uint16_t>(rdata_frame[1] & 0xffU) <<  0U
            );
        dnskey.protocol  = rdata_frame[2];
        dnskey.algorithm = static_cast<security_algorithm>(rdata_frame[3]);
        rdata_frame = rdata_frame.subspan(4);
        dnskey.public_key = rdata_frame;
        rdata = std::move(dnskey);
      }
      else if (type == rr_type::RRSIG)
      {
        if (rdata_frame.size() < 18)
          return std::nullopt;
        rrsig_rdata rrsig;
        rrsig.covered_type = static_cast<rr_type>(
              static_cast<std::uint16_t>(rdata_frame[ 0] & 0xffU) <<  8U
            | static_cast<std::uint16_t>(rdata_frame[ 1] & 0xffU) <<  0U
            );
        rrsig.algorithm = static_cast<security_algorithm>(rdata_frame[2]);
        rrsig.labels    = rdata_frame[3];
        rrsig.original_ttl = std::chrono::duration<std::uint32_t>(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 4] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 5] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[ 6] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[ 7] & 0xffU) <<  0U
          ));
        rrsig.expiration = std::chrono::duration<std::uint32_t>(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 8] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 9] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[10] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[11] & 0xffU) <<  0U
          ));
        rrsig.inception = std::chrono::duration<std::uint32_t>(
            static_cast<std::uint32_t>(
              static_cast<std::uint32_t>(rdata_frame[12] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[13] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[14] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[15] & 0xffU) <<  0U
          ));
        rrsig.key_tag = static_cast<std::uint16_t>(
              static_cast<std::uint16_t>(rdata_frame[16] & 0xffU) <<  8U
            | static_cast<std::uint16_t>(rdata_frame[17] & 0xffU) <<  0U
            );
        rdata_frame = rdata_frame.subspan(18);
        if (auto name = parse_domain_name(frame, rdata_frame, 0|label_type_mask::normal); name)
        {
          rrsig.signer_name = std::move(name->first);
          rdata_frame = name->second;
        }
        else
        {
          return std::nullopt;
        }
        rrsig.signature = rdata_frame;
        rdata = std::move(rrsig);
      }
      else if (type == rr_type::NSEC)
      {
        auto next_domain_name  = parse_domain_name(frame, rdata_frame, 0|label_type_mask::normal);
        auto types             = next_domain_name ? parse_type_bit_map(next_domain_name->second) : std::optional<std::set<rr_type>>(std::nullopt);
        if (!next_domain_name || !types)
          return std::nullopt;
        rdata = nsec_rdata{std::move(next_domain_name->first), std::move(*types)};
      }
      else if (type == rr_type::NSEC3)
      {
        nsec3_rdata nsec;
        if (rdata_frame.size() < 5)
          return std::nullopt;
        nsec.hash_algo = static_cast<digest_algorithm>(rdata_frame[0]);
        const auto flags = rdata_frame[1];
        nsec.opt_out = flags & 0x1;
        nsec.iterations = static_cast<std::uint16_t>(
              static_cast<std::uint16_t>(rdata_frame[2] & 0xffU) <<  8U
            | static_cast<std::uint16_t>(rdata_frame[3] & 0xffU) <<  0U
            );
        const auto salt_length = rdata_frame[4];
        if (rdata_frame.size() < 5 + salt_length + 1)
          return std::nullopt;
        nsec.salt = rdata_frame.subspan(5, salt_length);
        rdata_frame = rdata_frame.subspan(5 + salt_length);
        const auto hash_length = rdata_frame[0];
        if (rdata_frame.size() < 1 + hash_length)
          return std::nullopt;
        nsec.next_hashed_name = rdata_frame.subspan(1, hash_length);
        rdata_frame = rdata_frame.subspan(1 + hash_length);
        if (auto types = parse_type_bit_map(rdata_frame);
            types)
          nsec.types = std::move(*types);
        else
          return std::nullopt;
        rdata = std::move(nsec);
      }
      else if (rdclass == rr_class::IN && type == rr_type::A)
      {
        if (rdata_frame.size() != decltype(a_rdata::addr)::extent)
          return std::nullopt;
        rdata = a_rdata{rdata_frame};
      }
      else if (rdclass == rr_class::IN && type == rr_type::AAAA)
      {
        if (rdata_frame.size() != decltype(aaaa_rdata::addr)::extent)
          return std::nullopt;
        rdata = aaaa_rdata{rdata_frame};
      }
      else if (type == rr_type::OPT)
      {
        const auto udp_payload_size = static_cast<std::uint16_t>(rdclass);
        const auto extended_rcode   = static_cast<dns::rcode>(((ttl.count() >> 20) & 0xff0) | (static_cast<std::uint16_t>(rcode) & 0x0f));
        const auto edns_version     = static_cast<std::uint8_t>(ttl.count() >> 16);
        const auto flags            = static_cast<std::uint16_t>(ttl.count());
        const bool dnssec_ok        = flags & 0b1000'0000'0000'0000;
        edns_options options;
        while (!rdata_frame.empty())
        {
          if (rdata_frame.size() < 4)
            return std::nullopt;
          const auto code = static_cast<option_code>(
                static_cast<std::uint16_t>(rdata_frame[0] & 0xffU) <<  8U
              | static_cast<std::uint16_t>(rdata_frame[1] & 0xffU) <<  0U
              );
          const auto length = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(rdata_frame[2] & 0xffU) <<  8U
              | static_cast<std::uint16_t>(rdata_frame[3] & 0xffU) <<  0U
              );
          if (rdata_frame.size() < 4 + length)
            return std::nullopt;
          options.emplace(code, rdata_frame.subspan(4, length));
          rdata_frame = rdata_frame.subspan(4 + length);
        }
	rdata = opt_rdata{
              udp_payload_size
            , extended_rcode
            , edns_version
            , flags
            , dnssec_ok
            , std::move(options)
          };
      }

      rr rr{
          std::move(labels)
        , type
        , rdclass
        , ttl
        , std::move(rdata)
      };
      rrset.push_back(std::move(rr));
      cur = cur.subspan(10 + rdlength);
    }

    std::optional<opt_rdata> edns;
    for (const auto& rr : additionals)
    {
      if (const auto* const opt = std::get_if<opt_rdata>(&rr.rdata))
      {
        if (edns)
          return std::nullopt;

        edns = *opt;
        rcode = edns->extended_rcode;
      }
    }

    if (is_response)
      return reply{txid, rcode, is_authoritative_answer, is_truncated, is_recursion_available, authentic_data, checking_disabled, std::move(edns), std::move(questions), std::move(answers), std::move(authorities), std::move(additionals)};
    else
      return query{txid, opcode, is_recursion_desired, authentic_data, checking_disabled, std::move(edns), std::move(questions), std::move(answers), std::move(authorities), std::move(additionals)};
  }
}
