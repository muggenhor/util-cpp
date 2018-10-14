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

#ifndef INCLUDED_DNS_DNS_HPP
#define INCLUDED_DNS_DNS_HPP

#include <chrono>
#include <cstdint>
#include <gsl/span>
#include <iosfwd>
#include <optional>
#include <set>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <variant>
#include <vector>
#include "expected.hpp"

namespace dns
{
  enum class msgopcode : std::uint8_t
  {
    // RFC 1035: Domain names: Implementation and Specification
    query = 0U,
    inverse_query [[deprecated("Obsoleted by RFC 3425 - use PTR records instead")]] = 1U,
    status_request = 2U,

    // RFC 1996: A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
    notify = 4U,

    // RFC 2136: Dynamic Updates in the Domain Name System (DNS UPDATE)
    update = 5U,
  };

  enum class rr_type : std::uint16_t
  {
    // RFC 883: Domain names: Implementation and Specification
    MD [[deprecated("Obsoleted by RFC 973 - use MX")]] = 3U,
    MF [[deprecated("Obsoleted by RFC 973 - use MX")]] = 4U,
    MB [[deprecated("not used")]] = 7U,
    MG [[deprecated("not used")]] = 8U,
    MR [[deprecated("not used")]] = 9U,
    MINFO [[deprecated("not used")]] = 14U,
    WKS [[deprecated("Obsoleted by RFC 1123 and 1127")]] = 11U,

    // RFC 1035: Domain names: Implementation and Specification
    A = 1U,
    NS = 2U,
    CNAME = 5U,
    SOA = 6U,
    NULL_ = 10U,
    PTR = 12U,
    HINFO = 13U,
    MX = 15U,
    TXT = 16U,
    // RFC 6891: Extension Mechanisms for DNS (EDNS(0))
    OPT = 41U,

    // RFC 1183: New DNS RR Definitions
    RP = 17U,
    AFSDB = 18U,
    X25 [[deprecated("not used")]] = 19U,
    ISDN [[deprecated("not used")]] = 20U,
    RT [[deprecated("not used")]] = 21U,

    // RFC 1348: DNS NSAP RRs
    NSAP [[deprecated("not used")]] = 22U,
    NSAP_PTR [[deprecated("Obsoleted by RFC 1637 - use PTR instead")]] = 23U,

    // RFC 2163
    PX = 26U,

    // RFC 1712: DNS Encoding of Geographical Location
    GPOS [[deprecated("Obsoleted by RFC 1876")]] = 27U,

    // RFC 2535: Domain Name System Security Extensions
    SIG [[deprecated("Obsoleted by RFC 3755")]] = 24U,
    KEY [[deprecated("Obsoleted by RFC 3755")]] = 25U,
    NXT [[deprecated("Obsoleted by RFC 3755")]] = 30U,

    // RFC 3596: DNS Extensions to Support IP Version 6
    AAAA = 28U,

    // RFC 1876: A Means for Expressing Location Information in the Domain Name System
    LOC = 29U,

    // Expired draft: http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
    EID [[deprecated("not used")]] = 31U,
    NIMLOC [[deprecated("not used")]] = 32U,

    // RFC 2782: A DNS RR for specifying the location of services
    SRV = 33U,

    // Expired ATM address
    ATMA [[deprecated("not used")]] = 34U,

    // RFC 3403: Dynamic Delegation Discovery System
    NAPTR = 35U,

    // RFC 2230: Key Exchange Delegation Record for the DNS
    KX = 36U,

    // RFC 4398: Storing Certificates in the Domain Name System
    CERT = 37U,

    // RFC 2874
    A6 [[deprecated("Obsoleted by RFC 6563")]] = 38U,

    // RFC 6672: DNAME Redirection in the DNS
    DNAME = 39U,

    // Expired Kitchen Sink draft: http://tools.ietf.org/html/draft-eastlake-kitchen-sink
    SINK [[deprecated("not used")]] = 40U,

    // RFC 3123: A DNS RR Type for Lists of Address Prefixes
    APL [[deprecated("not used")]] = 42U,

    // RFC 4034: Resource Records for the DNS Security Extensions
    DS = 43U,
    RRSIG = 46U,
    NSEC = 47U,
    DNSKEY = 48U,

    // RFC 4255: Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
    SSHFP = 44U,

    // RFC 4025: A Method for Storing IPsec Keying Material in DNS
    IPSECKEY = 45U,

    // RFC 4701: A DNS Resource Record (RR) for Encoding
    //    Dynamic Host Configuration Protocol (DHCP) Information
    DHCID = 49U,

    // RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
    NSEC3 = 50U,
    NSEC3PARAM = 51U,

    // RFC 8162: Using Secure DNS to Associate Certificates with Domain Names for S/MIME
    SMIMEA = 53U,

    // RFC 6698: The DNS-Based Authentication of Named Entities (DANE)
    //              Transport Layer Security (TLS) Protocol: TLSA
    TLSA = 52U,

    // RFC 8005: Host Identity Protocol (HIP) Domain Name System (DNS) Extension
    HIP = 55U,

    // RFC 7344: Automating DNSSEC Delegation Trust Maintenance
    CDS = 59U,
    CDNSKEY = 60U,

    // RFC 7929: DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP
    OPENPGPKEY = 61U,

    // RFC 7477: Child-To-Parent Synchronization
    CSYNC = 62U,

    // RFC 4408: Sender Policy Framework
    SPF [[deprecated("Obsoleted by RFC 7208")]] = 99U,

    // RFC 7043: Resource Records for EUI-48 and EUI-64 Addresses
    EUI48 = 108U,
    EUI64 = 109U,

    // RFC 2930: Secret Key Establishment for DNS
    TKEY = 249U,

    // RFC 2845: Secret Key Transaction Authentication for DNS
    TSIG = 250U,

    // RFC 883: Domain names: Implementation and Specification
    MAILB [[deprecated("not used")]] = 253U,
    MAILA [[deprecated("Obsoleted by RFC 973 - use MX")]] = 254U,

    // RFC 7553: The Uniform Resource Identifier (URI) DNS Resource Record
    URI = 256U,

    // RFC 6844: DNS Certification Authority Authorization (CAA) Resource Record
    CAA = 257U,

    // Proposal for DNSSEC deployment without signed root: http://www.watson.org/~weiler/INI1999-19.pdf
    TA = 32768U,

    // RFC 4431: DNSSEC Lookaside Validation
    DLV = 32769U,

    // query-only types

    // RFC 1996
    IXFR = 251U,

    // RFC 1035: Domain names: Implementation and Specification
    AXFR = 252U,
    ANY = 255U,
  };

  enum class rr_class : std::uint16_t
  {
    IN = 1U,
    CS [[deprecated("Obsoleted by RFC 1035")]] = 2U,
    CH = 3U,
    HS = 4U,

    // query-only classes
    NONE = 254U,
    ANY = 255U,
  };

  // EDNS0 option codes
  enum class option_code : std::uint16_t
  {
    // http://files.dns-sd.org/draft-sekar-dns-llq.txt: DNS Long-Lived Queries
    LLQ                 =     1U,

    // http://files.dns-sd.org/draft-sekar-dns-ul.txt: Dynamic DNS Update Leases
    UL                  =     2U,

    // RFC 5001: DNS Name Server Identifier (NSID) Option
    NSID                =     3U,

    // RFC 6975: Signaling Cryptographic Algorithm Understanding in
    //                     DNS Security Extensions
    DAU                 =     5U,
    DHU                 =     6U,
    N3U                 =     7U,

    // RFC 7871: Client Subnet in DNS Queries
    edns_client_subnet  =     8U,

    // RFC 7314: Extension Mechanisms for DNS (EDNS) EXPIRE Option
    EDNS_EXPIRE         =     9U,

    // RFC 7873: Domain Name System (DNS) Cookies
    COOKIE              =    10U,

    // RFC 7828: The edns-tcp-keepalive EDNS0 Option
    edns_tcp_keepalive  =    11U,

    // RFC 7830: The EDNS(0) Padding Option
    padding             =    12U,

    // RFC 7901: CHAIN Query Requests in DNS
    CHAIN               =    13U,

    // RFC 8145: Signaling Trust Anchor Knowledge in DNS Security Extensions
    edns_key_tag        =    14U,

    // https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2
    device_id           = 26946U,
  };

  enum class digest_algorithm : std::uint8_t
  {
    // RFC 4034: Resource Records for the DNS Security Extensions
    SHA1      = 1U,
    // RFC 4509: Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
    SHA256    = 2U,
    // RFC 5933: Use of GOST Signature Algorithms in DNSKEY
    //             and RRSIG Resource Records for DNSSEC
    ECC_GOST  = 3U,
    // RFC 6605: Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
    SHA384    = 4U,
  };

  enum class security_algorithm : std::uint8_t
  {
    // RFC 4034: Resource Records for the DNS Security Extensions
    DELETE              =  0U,
    // RFC 4034: Resource Records for the DNS Security Extensions
    RSAMD5              =  1U,
    // RFC 2539: Storage of Diffie-Hellman Keys in the Domain Name System
    DH                  =  2U,
    // RFC 3755: Legacy Resolver Compatibility for Delegation Signer
    DSA                 =  3U,
    // RFC 3110: RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System
    RSASHA1             =  5U,
    // RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
    DSA_NSEC3_SHA1      =  6U,
    RSASHA1_NSEC3_SHA1  =  7U,
    // RFC 5702: Use of SHA-2 Algorithms with RSA in
    //       DNSKEY and RRSIG Resource Records for DNSSEC
    RSASHA256           =  8U,
    RSASHA512           = 10U,
    // RFC 5933: Use of GOST Signature Algorithms in DNSKEY
    //             and RRSIG Resource Records for DNSSEC
    ECC_GOST            = 12U,
    // RFC 6605: Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
    ECDSAP256SHA256     = 13U,
    ECDSAP384SHA384     = 14U,
    // RFC 8080: Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC
    ED25519             = 15U,
    ED448               = 16U,
  };

  enum class rcode : unsigned
  {
    no_error        =  0U,
    format_error    =  1U,
    server_failure  =  2U,
    name_error      =  3U,
    not_implemented =  4U,
    refused         =  5U,
    yxdomain        =  6U,
    yxrrset         =  7U,
    nxrrset         =  8U,
    notauth         =  9U,
    notzone         = 10U,
  };

  const std::error_category& rcode_category() noexcept;

  inline std::error_code make_error_code(rcode e) noexcept
  {
    return std::error_code(static_cast<int>(e), rcode_category());
  }

  std::ostream& operator<<(std::ostream& os, msgopcode o);
  std::ostream& operator<<(std::ostream& os, rr_type r);
  std::ostream& operator<<(std::ostream& os, rr_class r);
  std::ostream& operator<<(std::ostream& os, option_code o);
  std::ostream& operator<<(std::ostream& os, digest_algorithm algo);
  std::ostream& operator<<(std::ostream& os, security_algorithm algo);

  using unknown_rdata = gsl::span<const std::uint8_t>;
  using name = std::vector<std::string_view>;

  struct mx_rdata
  {
    std::uint16_t preference;
    name          exchange;
  };

  struct soa_rdata
  {
    name                                 authoritative_name_server;
    name                                 hostmaster;
    std::uint32_t                        serial;
    std::chrono::duration<std::uint32_t> refresh;
    std::chrono::duration<std::uint32_t> retry;
    std::chrono::duration<std::uint32_t> expiry;
    std::chrono::duration<std::uint32_t> ttl;
  };

  struct txt_rdata
  {
    std::vector<std::string_view> strings;
  };

  struct question
  {
    name                                  labels;
    rr_type                               rdtype;
    rr_class                              rdclass;
  };

  struct a_rdata
  {
    gsl::span<const uint8_t, 4> addr;
  };

  struct aaaa_rdata
  {
    gsl::span<const uint8_t, 16> addr;
  };

  struct rrsig_rdata
  {
    rr_type                               covered_type;
    security_algorithm                    algorithm;
    std::uint8_t                          labels;
    std::chrono::duration<std::uint32_t>  original_ttl;
    std::chrono::duration<std::uint32_t>  expiration;
    std::chrono::duration<std::uint32_t>  inception;
    std::uint16_t                         key_tag;
    name                                  signer_name;
    gsl::span<const uint8_t>              signature;
  };

  struct nsec_rdata
  {
    name              next_domain_name;
    std::set<rr_type> types;
  };

  struct nsec3_rdata
  {
    digest_algorithm              hash_algo;
    bool                          opt_out;
    std::uint16_t                 iterations;
    gsl::span<const std::uint8_t> salt;
    gsl::span<const std::uint8_t> next_hashed_name;
    std::set<rr_type>             types;
  };

  struct ds_rdata
  {
    std::uint16_t                 key_tag;
    security_algorithm            algorithm;
    digest_algorithm              digest_type;
    gsl::span<const std::uint8_t> digest;
  };

  struct dnskey_rdata
  {
    std::uint16_t                 flags;
    std::uint8_t                  protocol;
    security_algorithm            algorithm;
    gsl::span<const std::uint8_t> public_key;
  };

  using edns_options = std::unordered_map<option_code, gsl::span<const std::uint8_t>>;

  struct opt_rdata
  {
    std::uint16_t udp_payload_size;
    dns::rcode    extended_rcode;
    std::uint8_t  edns_version;
    std::uint16_t flags;
    bool          dnssec_ok;
    edns_options  options;
  };

  struct rr
  {
    name                                  labels;
    rr_type                               rdtype;
    rr_class                              rdclass;
    std::chrono::duration<std::uint32_t>  ttl;
    std::variant<
        unknown_rdata                
      , mx_rdata
      , soa_rdata
      , txt_rdata
      , rrsig_rdata
      , nsec_rdata
      , nsec3_rdata
      , ds_rdata
      , dnskey_rdata
      , a_rdata
      , aaaa_rdata
      , name                           
      , opt_rdata
      >                                   rdata;
  };

  struct message
  {
    std::uint16_t txid;
    bool is_response;
    msgopcode opcode;
    dns::rcode rcode;
    bool is_authoritative_answer;
    bool is_truncated;
    bool is_recursion_desired;
    bool is_recursion_available;
    bool authentic_data;
    bool checking_disabled;
    std::optional<opt_rdata> edns;

    std::vector<question> questions;
    std::vector<rr>       answers;
    std::vector<rr>       authority;
    std::vector<rr>       additional;
  };

  template <typename T>
  using expected = ::util::expected<T, std::error_code>;
}

namespace std
{
  template <>
  struct is_error_code_enum<::dns::rcode> : public true_type {};
}

#endif /* INCLUDED_DNS_DNS_HPP */
