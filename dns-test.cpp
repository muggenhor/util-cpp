#include "dns.hpp"
#include "overload.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <utility>

template <typename InputIterator, typename EndIterator>
std::pair<std::optional<std::uint16_t>, InputIterator> read_u16(InputIterator first, const EndIterator last)
{
  if (first == last)
    return {std::nullopt, std::move(first)};
  const std::uint8_t msb = *first++;
  if (first == last)
    return {std::nullopt, std::move(first)};
  const std::uint8_t lsb = *first++;
  return {static_cast<std::uint16_t>(msb << 8 | lsb), std::move(first)};
}

template <typename InputIterator, typename EndIterator>
std::error_code process_pkts(InputIterator first, const EndIterator last)
{
  std::error_code err;
  std::vector<std::uint8_t> frame;
  while (first != last)
  {
    using std::cout;
    frame.clear();

    const auto length = [&] {
      auto [len, iter] = read_u16(std::move(first), last);
      first = std::move(iter);
      return len;
    }();
    if (!length)
    {
      cout << "\x1B[31m" "couldn't read length: too little data" "\x1B[39m\n";
      return make_error_code(dns::parser_error::not_enough_data);
    }
    else
    {
      cout << "frame len: " << *length << '\n';
      for (unsigned i = 0; length && i < *length; ++i)
      {
        if (first == last)
        {
          cout << "\x1B[31m" "less octets available than specified frame length" "\x1B[39m: " << frame.size() << '\n';
          return make_error_code(dns::parser_error::not_enough_data);
        }
        frame.push_back(*first++);
      }
    }
    if (auto msg = dns::parse(frame); msg)
    {
      const auto print_name = [] (const dns::name& labels) {
          for (const auto& label : labels)
            cout << label << '.';
        };

      cout << "txid: " << msg->txid;
      if (msg->is_response)
      {
        if (msg->rcode)
          cout << "; status: " << msg->rcode.category().name() << ':' << msg->rcode.message();
      }
      else
      {
        cout << "; opcode: " << msg->opcode;
      }
      if (msg->authentic_data || msg->checking_disabled)
        cout << "; flags:";
      if (msg->authentic_data)
        cout << " ad";
      if (msg->checking_disabled)
        cout << " cd";
      cout << '\n';
      cout << "  questions (" << msg->questions.size() << "):\n";
      for (const auto& q : msg->questions)
      {
        cout << "    ";
        print_name(q.labels);
        cout << ' ' << q.rdclass << ' ' << q.rdtype << '\n';
      }

      const auto print_rr = [&] (const dns::rr& rr) {
          cout << "    ";
          print_name(rr.labels);
          if (!std::holds_alternative<dns::opt_rdata>(rr.rdata))
            // These fields are repurposed by OPT pseudo RRs
            cout << ' ' << rr.ttl.count() << ' ' << rr.rdclass;
          else
            cout << " - -";
          cout << ' ' << rr.rdtype;
          visit(util::overload(
              [&](const dns::name& name) {
                cout << ' ';
                print_name(name);
              },
              [&](const dns::mx_rdata& mx) {
                cout << ' ' << mx.preference << ' ';
                print_name(mx.exchange);
              },
              [&](const dns::soa_rdata& soa) {
                cout << ' ';
                print_name(soa.authoritative_name_server);
                cout << ' ';
                print_name(soa.hostmaster);
                cout
                  << ' ' << soa.serial
                  << ' ' << soa.refresh.count()
                  << ' ' << soa.retry.count()
                  << ' ' << soa.expiry.count()
                  << ' ' << soa.ttl.count()
                  ;
              },
              [](const dns::txt_rdata& txt) {
                for (const auto& str : txt.strings)
                {
                  cout << " \"" << str << '"';
                }
              },
              [](const dns::a_rdata& a) {
                char sep = ' ';
                for (const unsigned group : a.addr)
                {
                  cout << sep << group;
                  sep = '.';
                }
              },
              [](const dns::aaaa_rdata& aaaa) {
                const auto flags = cout.flags();
                const int addr[] = {
                  aaaa.addr[ 0] << 8 | aaaa.addr[ 1],
                  aaaa.addr[ 2] << 8 | aaaa.addr[ 3],
                  aaaa.addr[ 4] << 8 | aaaa.addr[ 5],
                  aaaa.addr[ 6] << 8 | aaaa.addr[ 7],
                  aaaa.addr[ 8] << 8 | aaaa.addr[ 9],
                  aaaa.addr[10] << 8 | aaaa.addr[11],
                  aaaa.addr[12] << 8 | aaaa.addr[13],
                  aaaa.addr[14] << 8 | aaaa.addr[15],
                };
                char sep = ' ';
                cout << std::hex;
                for (const unsigned group : addr)
                {
                  cout << sep << group;
                  sep = ':';
                }
                cout.flags(flags);
              },
              [&](const dns::ds_rdata& ds) {
                cout
                  << ' ' << ds.key_tag
                  << ' ' << ds.algorithm
                  << ' ' << ds.digest_type
                  ;

                const auto fill  = cout.fill();
                const auto flags = cout.flags();

                cout << std::hex << std::setfill('0') << ' ';
                for (const unsigned octet : ds.digest)
                  cout << std::setw(2) << octet;

                cout.fill(fill);
                cout.flags(flags);
              },
              [&](const dns::dnskey_rdata& dnskey) {
                cout
                  << ' ' << dnskey.flags
                  << ' ' << static_cast<unsigned>(dnskey.protocol)
                  << ' ' << dnskey.algorithm
                  ;

                const auto fill  = cout.fill();
                const auto flags = cout.flags();

                cout << std::hex << std::setfill('0') << ' ';
                for (const unsigned octet : dnskey.public_key)
                  cout << std::setw(2) << octet;

                cout.fill(fill);
                cout.flags(flags);
              },
              [&](const dns::rrsig_rdata& rrsig) {
                cout
                  << ' ' << rrsig.covered_type
                  << ' ' << rrsig.algorithm
                  << ' ' << static_cast<unsigned>(rrsig.labels)
                  << ' ' << rrsig.original_ttl.count()
                  << ' ' << rrsig.expiration.count()
                  << ' ' << rrsig.inception.count()
                  << ' ' << rrsig.key_tag
                  << ' '
                  ;
                print_name(rrsig.signer_name);

                const auto fill  = cout.fill();
                const auto flags = cout.flags();

                cout << std::hex << std::setfill('0') << ' ';
                for (const unsigned octet : rrsig.signature)
                  cout << std::setw(2) << octet;

                cout.fill(fill);
                cout.flags(flags);
              },
              [&](const dns::nsec_rdata& nsec) {
                cout << ' ';
                print_name(nsec.next_domain_name);
                for (const auto type : nsec.types)
                  cout << ' ' << type;
              },
              [&](const dns::nsec3_rdata& nsec) {
                cout
                  << ' ' << nsec.hash_algo
                  << ' ' << nsec.opt_out
                  << ' ' << static_cast<unsigned>(nsec.iterations)
                  ;

                const auto fill  = cout.fill();
                const auto flags = cout.flags();

                cout << std::hex << std::setfill('0') << ' ';
                for (const unsigned octet : nsec.salt)
                  cout << std::setw(2) << octet;
                if (nsec.salt.empty())
                  cout << '-';

                cout << std::hex << std::setfill('0') << ' ';
                // TODO: format as base32 instead
                for (const unsigned octet : nsec.next_hashed_name)
                  cout << std::setw(2) << octet;
                if (nsec.next_hashed_name.empty())
                  cout << '-';

                cout.fill(fill);
                cout.flags(flags);

                for (const auto type : nsec.types)
                  cout << ' ' << type;
              },
              [](const dns::opt_rdata& opt) {
                const auto fill  = cout.fill();
                const auto flags = cout.flags();

                cout
                  << " version: " << std::dec << static_cast<unsigned>(opt.edns_version)
                  << "; flags:";
                if (opt.dnssec_ok)
                  cout << " do";
                cout
                  << "; UDP size: " << std::dec << opt.udp_payload_size << " B"
                  << "; ext-rcode: " << make_error_code(opt.extended_rcode).message()
                  ;
                for (const auto& option : opt.options)
                {
                  cout << "; " << std::dec << option.first << ' ' << std::hex << std::setfill('0');
                  for (const unsigned octet : option.second)
                    cout << std::setw(2) << octet;
                }

                cout.fill(fill);
                cout.flags(flags);
              },
              [](const dns::unknown_rdata& data) {
                const auto fill  = cout.fill();
                const auto flags = cout.flags();

                cout << std::hex << std::setfill('0') << ' ';
                for (const unsigned octet : data)
                  cout << std::setw(2) << octet;

                cout.fill(fill);
                cout.flags(flags);
              }
            ), rr.rdata);
          cout << '\n';
        };

      cout << "  answers (" << msg->answers.size() << "):\n";
      for (const auto& rr : msg->answers)
        print_rr(rr);
      cout << "  authority (" << msg->authority.size() << "):\n";
      for (const auto& rr : msg->authority)
        print_rr(rr);
      cout << "  additional (" << msg->additional.size() << "):\n";
      for (const auto& rr : msg->additional)
        print_rr(rr);
    }
    else
    {
      cout << "\x1B[31m" "invalid DNS packet" "\x1B[39m: "
        << msg.error().category().name() << ':' << msg.error().message() << '\n';
      err = msg.error();
    }
  }

  return err;
}

int main(const int argc, const char** const argv)
{
  std::error_code err;
  if (argc < 2)
  {
    err = process_pkts(std::istreambuf_iterator(std::cin), std::istreambuf_iterator<char>());
  }
  else
  {
    for (int i = 1; i < argc; ++i)
    {
      std::ifstream input{argv[i], std::ios_base::in | std::ios_base::binary};
      auto n = process_pkts(std::istreambuf_iterator(input), std::istreambuf_iterator<char>());
      if (n)
        err = n;
    }
  }

  return err ? 1 : 0;
}
