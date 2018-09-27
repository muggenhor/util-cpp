#include <climits>
#include <cstddef>
#include <optional>
#include <system_error>
#include "dns.hpp"

namespace dns
{
  const std::error_category& dns_category() noexcept
  {
    struct dns_error_category final : public std::error_category
    {
      const char* name() const noexcept override { return "dns"; }

      std::string message(int i) const override
      {
        switch (static_cast<dns::errc>(i))
        {
          case errc::no_error:
            break;
          case errc::format_error:
            return "format error";
          case errc::server_failure:
            return "server failure";
          case errc::name_error:
            return "no such name exists";
          case errc::not_implemented:
            return "not implemented";
          case errc::refused:
            return "refused";
          case errc::yxdomain:
            return "name exists when it shouldn't";
          case errc::yxrrset:
            return "rrset exists when it shouldn't";
          case errc::nxrrset:
            return "no such rrset exists";
          case errc::notauth:
            return "server not authoritative for specified zone";
          case errc::notzone:
            return "a specified name is outside of the specified zone";
        }

        char msg[64];
        snprintf(msg, sizeof(msg), "unknown %s error: %d", this->name(), i);
        return std::string(msg);
      }

      std::error_condition default_error_condition(int i) const noexcept override
      {
        switch (static_cast<dns::errc>(i))
        {
          case errc::no_error:
            return {i, *this};
          case errc::format_error:
            break;
          case errc::server_failure:
            break;
          case errc::name_error:
            break;
          case errc::not_implemented:
            return std::errc::function_not_supported;
          case errc::refused:
            return std::errc::operation_not_permitted;
          case errc::yxdomain:
            break;
          case errc::yxrrset:
            break;
          case errc::nxrrset:
            break;
          case errc::notauth:
            break;
          case errc::notzone:
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
    std::optional<std::pair<std::vector<std::string_view>, gsl::span<const std::uint8_t> /* unused remainder of name_frame */>>
      parse_domain_name(
            const gsl::span<const std::uint8_t> frame
          , gsl::span<const std::uint8_t> name_frame
        )
    {
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
        const auto label_type = [&] {
            if (const auto type = static_cast<std::uint8_t>(label_size & 0b1100'0000);
                type == 0b0100'0000)
              return label_size;
            else
              return type;
          }();

        switch (label_type)
        {
          // Handle name pointers, which terminate a sequence of labels
          case 0b1100'0000:
          {
            if (pos.empty())
              return std::nullopt;
            // prevent infinite loops
            if (pointer_labels_followed++ > frame.size() / 4)
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
          case 0b0000'0000:
          {
            if (pos.size() < label_size)
              return std::nullopt;
            if (label_size <= 0)
              goto end_loop;

            labels.emplace_back(reinterpret_cast<const char*>(pos.data()), label_size);
            pos = pos.subspan(label_size);
            break;
          }
          default:
            return std::nullopt;
        }
      }
end_loop:
      if (!name_is_compressed)
        name_frame = pos;

      return std::make_pair(std::move(labels), name_frame);
    }
  }

  std::optional<message> parse(gsl::span<const std::uint8_t> frame)
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
    errc rcode                           {(flags >>  0U) & 0xfU};

    // RFC 2535 6.1
    const bool authentic_data          = (flags >>  5U) & 0x1U;
    const bool checking_disabled       = (flags >>  4U) & 0x1U;

    std::uint16_t udp_payload_size = 512U;
    std::optional<std::uint8_t> edns_version;
    bool dnssec_ok = false;
    edns_options options;

    const std::uint16_t question_count   = static_cast<std::uint16_t>(frame[ 4]) << 8U | frame[ 5];
    const std::uint16_t answer_count     = static_cast<std::uint16_t>(frame[ 6]) << 8U | frame[ 7];
    const std::uint16_t authority_count  = static_cast<std::uint16_t>(frame[ 8]) << 8U | frame[ 9];
    const std::uint16_t additional_count = static_cast<std::uint16_t>(frame[10]) << 8U | frame[11];

    std::uint16_t cur = 12;
    std::vector<question> questions;
    questions.reserve(question_count);
    for (std::uint16_t i = 0; i < question_count; ++i)
    {
      if (cur >= frame.size())
        return std::nullopt;

      std::vector<std::string_view> labels;
      if (auto name = parse_domain_name(frame, frame.subspan(cur)); name)
      {
        labels = std::move(name->first);
        cur = name->second.data() - frame.data();
      }
      else
      {
        return std::nullopt;
      }
      if (cur + 4 > frame.size())
        return std::nullopt;

      question question{
          std::move(labels)
        , rr_type {static_cast<std::uint16_t>(static_cast<std::uint16_t>(frame[cur + 0]) << 8U | frame[cur + 1])}
        , rr_class{static_cast<std::uint16_t>(static_cast<std::uint16_t>(frame[cur + 2]) << 8U | frame[cur + 3])}
      };
      questions.push_back(std::move(question));
      cur += 4;
    }

    std::vector<rr> answers;
    answers.reserve(answer_count);
    std::vector<rr> authorities;
    authorities.reserve(authority_count);
    std::vector<rr> additionals;
    additionals.reserve(additional_count);

    bool seen_opt_rr = false;
    for (std::size_t i = 0; i < static_cast<std::uint16_t>(answer_count + authority_count + additional_count); ++i)
    {
      auto& rrset = i < answer_count                   ? answers
                  : i < answer_count + authority_count ? authorities
                  :                                      additionals
                  ;

      if (cur >= frame.size())
        return std::nullopt;

      std::vector<std::string_view> labels;
      if (auto name = parse_domain_name(frame, frame.subspan(cur)); name)
      {
        labels = std::move(name->first);
        cur = name->second.data() - frame.data();
      }
      else
      {
        return std::nullopt;
      }
      if (cur + 10 > frame.size())
        return std::nullopt;

      const auto rdlength = static_cast<std::uint16_t>(frame[cur + 8]) << 8U | frame[cur + 9];
      if (cur + 10 + rdlength > frame.size())
        return std::nullopt;

      const auto type    = static_cast<rr_type>(static_cast<std::uint16_t>(frame[cur + 0]) << 8U | frame[cur + 1]);
      const auto rdclass = static_cast<rr_class>(static_cast<std::uint16_t>(frame[cur + 2]) << 8U | frame[cur + 3]);
      const std::chrono::duration<std::uint32_t> ttl{
          static_cast<std::uint32_t>(frame[cur + 4] & 0xffU) << 24U
        | static_cast<std::uint32_t>(frame[cur + 5] & 0xffU) << 16U
        | static_cast<std::uint32_t>(frame[cur + 6] & 0xffU) <<  8U
        | (frame[cur + 7] & 0xffU)};

      auto rdata_frame = frame.subspan(cur + 10, rdlength);
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
        const std::chrono::duration<std::int32_t> refresh(
            static_cast<std::int32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 4] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 5] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[ 6] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[ 7] & 0xffU) <<  0U
          ));
        const std::chrono::duration<std::int32_t> retry(
            static_cast<std::int32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 8] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 9] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[10] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[11] & 0xffU) <<  0U
          ));
        const std::chrono::duration<std::int32_t> expiry(
            static_cast<std::int32_t>(
              static_cast<std::uint32_t>(rdata_frame[12] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[13] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[14] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[15] & 0xffU) <<  0U
          ));
        const std::chrono::duration<std::int32_t> negative_ttl(
            static_cast<std::int32_t>(
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
        for (;;)
        {
          if (rdata_frame.size() < 1)
            return std::nullopt;
          const auto string_size = rdata_frame[0];
          rdata_frame = rdata_frame.subspan(1);
          if (rdata_frame.size() < string_size)
            return std::nullopt;
          txt.strings.emplace_back(reinterpret_cast<const char*>(rdata_frame.data()), string_size);
          rdata_frame = rdata_frame.subspan(string_size);
          if (rdata_frame.empty())
            break;
        }
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
            static_cast<std::int32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 4] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 5] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[ 6] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[ 7] & 0xffU) <<  0U
          ));
        rrsig.expiration = std::chrono::duration<std::uint32_t>(
            static_cast<std::int32_t>(
              static_cast<std::uint32_t>(rdata_frame[ 8] & 0xffU) << 24U
            | static_cast<std::uint32_t>(rdata_frame[ 9] & 0xffU) << 16U
            | static_cast<std::uint32_t>(rdata_frame[10] & 0xffU) <<  8U
            | static_cast<std::uint32_t>(rdata_frame[11] & 0xffU) <<  0U
          ));
        rrsig.inception = std::chrono::duration<std::uint32_t>(
            static_cast<std::int32_t>(
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
        // using this, instead of parse_domain_name, because it supports domain compression and that's not permitted for RRSIG
        for (;;)
        {
          if (rdata_frame.size() < 1)
            return std::nullopt;
          const auto string_size = rdata_frame[0];
          if (string_size & 0xc0)
            return std::nullopt;
          rdata_frame = rdata_frame.subspan(1);
          if (string_size <= 0)
            break;
          if (rdata_frame.size() < string_size)
            return std::nullopt;
          rrsig.signer_name.emplace_back(reinterpret_cast<const char*>(rdata_frame.data()), string_size);
          rdata_frame = rdata_frame.subspan(string_size);
        }
        rrsig.signature = rdata_frame;
        rdata = std::move(rrsig);
      }
      else if (type == rr_type::NSEC)
      {
        nsec_rdata nsec;
        // using this, instead of parse_domain_name, because it supports domain compression and that's not permitted for NSEC
        for (;;)
        {
          if (rdata_frame.size() < 1)
            return std::nullopt;
          const auto string_size = rdata_frame[0];
          if (string_size & 0xc0)
            return std::nullopt;
          rdata_frame = rdata_frame.subspan(1);
          if (string_size <= 0)
            break;
          if (rdata_frame.size() < string_size)
            return std::nullopt;
          nsec.next_domain_name.emplace_back(reinterpret_cast<const char*>(rdata_frame.data()), string_size);
          rdata_frame = rdata_frame.subspan(string_size);
          if (rdata_frame.empty())
            break;
        }
        for (; !rdata_frame.empty();)
        {
          if (rdata_frame.size() < 2)
            return std::nullopt;
          // RFC 4034 section 4.1.2: The Type Bit Maps Field
          const auto window = static_cast<std::uint16_t>(rdata_frame[0] << 8U);
          const auto bitmap_length = rdata_frame[1];
          if (bitmap_length < 1 || bitmap_length > 32)
            return std::nullopt;
          if (rdata_frame.size() < 2 + bitmap_length)
            return std::nullopt;
          const auto bitmap = rdata_frame.subspan(2, bitmap_length);
          rdata_frame = rdata_frame.subspan(2 + bitmap_length);
          unsigned idx = 0U;
          for (const unsigned octet : bitmap)
          {
            const unsigned offset = idx++;
            for (const unsigned bit : { 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, })
            {
              if (octet & (1U << (7 - bit)))
              {
                nsec.types.emplace(static_cast<rr_type>(window | (offset * 8U + bit)));
              }
            }
          }
        }
        rdata = std::move(nsec);
      }
      else if (type == rr_type::NSEC3)
      {
        nsec3_rdata nsec;
        // using this, instead of parse_domain_name, because it supports domain compression and that's not permitted for NSEC
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
        for (; !rdata_frame.empty();)
        {
          if (rdata_frame.size() < 2)
            return std::nullopt;
          // RFC 4034 section 4.1.2: The Type Bit Maps Field
          const auto window = static_cast<std::uint16_t>(rdata_frame[0] << 8U);
          const auto bitmap_length = rdata_frame[1];
          if (bitmap_length < 1 || bitmap_length > 32)
            return std::nullopt;
          if (rdata_frame.size() < 2 + bitmap_length)
            return std::nullopt;
          const auto bitmap = rdata_frame.subspan(2, bitmap_length);
          rdata_frame = rdata_frame.subspan(2 + bitmap_length);
          unsigned idx = 0U;
          for (const unsigned octet : bitmap)
          {
            const unsigned offset = idx++;
            for (const unsigned bit : { 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, })
            {
              if (octet & (1U << (7 - bit)))
              {
                nsec.types.emplace(static_cast<rr_type>(window | (offset * 8U + bit)));
              }
            }
          }
        }
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

      if (type == rr_type::OPT)
      {
        if (seen_opt_rr)
          return std::nullopt;
        seen_opt_rr = true;
        // RFC 6891, section 6.2.3: Values lower than 512 MUST be treated as equal to 512
        udp_payload_size = static_cast<std::uint16_t>(rdclass);
        rcode = static_cast<errc>(
            ((ttl.count() >> 24U) & 0xffU)
          | static_cast<std::uint32_t>(rcode));
        edns_version = static_cast<std::uint8_t>((ttl.count() >> 16U) & 0xffU);
        dnssec_ok = ttl.count() & 0x00008000U;

        while (!rdata_frame.empty())
        {
          if (rdata_frame.size() < 4)
            return std::nullopt;
          const auto code = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(rdata_frame[0] & 0xffU) <<  8U
              | static_cast<std::uint16_t>(rdata_frame[1] & 0xffU) <<  0U
              );
          const auto length = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(rdata_frame[2] & 0xffU) <<  8U
              | static_cast<std::uint16_t>(rdata_frame[3] & 0xffU) <<  0U
              );
          if (rdata_frame.size() < 4 + length)
            return std::nullopt;
          options.emplace(static_cast<option_code>(code), rdata_frame.subspan(4, length));
          rdata_frame = rdata_frame.subspan(4 + length);
        }
      }
      else
      {
        rr rr{
            std::move(labels)
          , type
          , rdclass
          , ttl
          , std::move(rdata)
        };
        rrset.push_back(std::move(rr));
      }
      cur += 10 + rdlength;
    }

    if (is_response)
      return reply{txid, rcode, is_authoritative_answer, is_truncated, is_recursion_available, authentic_data, checking_disabled, edns_version, udp_payload_size, dnssec_ok, std::move(questions), std::move(answers), std::move(authorities), std::move(additionals), std::move(options)};
    else
      return query{txid, opcode, is_recursion_desired, authentic_data, checking_disabled, edns_version, udp_payload_size, dnssec_ok, std::move(questions), std::move(answers), std::move(authorities), std::move(additionals), std::move(options)};
  }
}
