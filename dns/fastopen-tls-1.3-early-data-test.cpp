#include <algorithm>
#include <array>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>
#include <cassert>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>

#include "dns/parser.hpp"
#include "dns/serializer.hpp"
#include "overload.hpp"

#include <unistd.h>

class tcp_fastopen_connect
{
public:
  template <typename T> constexpr       int   level(T&&) const noexcept { return IPPROTO_TCP         ; }
  template <typename T> constexpr       int   name (T&&) const noexcept { return TCP_FASTOPEN_CONNECT; }
  template <typename T> constexpr const int*  data (T&&) const noexcept { return &val; }
  template <typename T> constexpr std::size_t size (T&&) const noexcept { return sizeof(val); }

  constexpr explicit tcp_fastopen_connect(bool v) noexcept
    : val(v ? 1 : 0)
  {}

  explicit constexpr operator bool() const noexcept { return static_cast<bool>(val); }

private:
  int val;
};

void perform_request(boost::asio::io_service& io, const char* const dns_server)
{
  using namespace std::literals;

  std::uint8_t tlsa_buf[2048];
  std::uint8_t buf[16385];

  const auto [tgt, tlsa_rec] = [&] {
    const boost::asio::ip::udp::endpoint bootstrap_tgt(boost::asio::ip::address_v4::from_string("127.0.0.53"), 53);
    boost::asio::ip::udp::socket sock(io, bootstrap_tgt.protocol());
    sock.connect(bootstrap_tgt);
    return monad::sequence(
      [&] {
        return dns::make_question(dns_server, dns::rr_type::AAAA)
          .map([&buf](auto&& msg) {
            return dns::serialize(std::forward<decltype(msg)>(msg), buf)
              .map([txid = msg.txid] (auto reply) {
                  return std::make_pair(txid, reply);
              });
          })
          .apply([&buf, &sock, &dns_server] (const auto txid, const auto request) -> dns::expected<boost::asio::ip::tcp::endpoint> {
              sock.send(boost::asio::buffer(request.data(), request.size()));
              const auto size = sock.receive(boost::asio::buffer(buf));
              auto reply = dns::parse(gsl::span<std::uint8_t>(buf, size));
              if (!reply)
                return util::unexpected(reply.error());
              if (!reply->is_response)
                throw std::system_error(make_error_code(std::errc::protocol_error), "received a non-response DNS message");
              if (reply->rcode != dns::rcode::no_error)
                return util::unexpected(reply->rcode);
              if (reply->is_truncated)
                throw std::system_error(make_error_code(std::errc::protocol_error), "received a truncated DNS reply");
              if (reply->txid != txid)
                throw std::system_error(make_error_code(std::errc::protocol_error), "DNS transaction ID mismatch");
              for (const auto& answer : reply->answers)
              {
#if 0
                std::string name;
                for (const auto& label : answer.labels)
                {
                  if (!name.empty())
                    name += '.';
                  name += label;
                }
                if (name != dns_server)
                  continue;
#endif
                if (const auto* const rr = std::get_if<dns::a_rdata>(&answer.rdata))
                {
                  using addr_t = boost::asio::ip::address_v4;
                  using bytes_t = addr_t::bytes_type;
                  return boost::asio::ip::tcp::endpoint(
                      addr_t(*reinterpret_cast<const bytes_t*>(rr->addr.data()))
                    , 853
                    );
                }
                if (const auto* const rr = std::get_if<dns::aaaa_rdata>(&answer.rdata))
                {
                  using addr_t = boost::asio::ip::address_v6;
                  using bytes_t = addr_t::bytes_type;
                  return boost::asio::ip::tcp::endpoint(
                      addr_t(*reinterpret_cast<const bytes_t*>(rr->addr.data()))
                    , 853
                    );
                }
              }
              return util::unexpected(make_error_code(dns::rcode::name_error));
          });
      },
      [&] {
        return dns::make_question("_853._tcp."s + dns_server, dns::rr_type::TLSA)
          .map([&buf](auto&& msg) {
            return dns::serialize(std::forward<decltype(msg)>(msg), buf)
              .map([txid = msg.txid] (auto reply) {
                  return std::make_pair(txid, reply);
              });
          })
          .apply([&tlsa_buf, &sock, &dns_server] (const auto txid, const auto request) -> dns::expected<dns::tlsa_rdata> {
              sock.send(boost::asio::buffer(request.data(), request.size()));
              const auto size = sock.receive(boost::asio::buffer(tlsa_buf));
              auto reply = dns::parse(gsl::span<std::uint8_t>(tlsa_buf, size));
              if (!reply)
                return util::unexpected(reply.error());
              if (!reply->is_response)
                throw std::system_error(make_error_code(std::errc::protocol_error), "received a non-response DNS message");
              if (reply->rcode != dns::rcode::no_error)
                return util::unexpected(reply->rcode);
              if (reply->is_truncated)
                throw std::system_error(make_error_code(std::errc::protocol_error), "received a truncated DNS reply");
              if (reply->txid != txid)
                throw std::system_error(make_error_code(std::errc::protocol_error), "DNS transaction ID mismatch");
#if 0
              const auto dns_server_tlsa = "_853._tcp"s + dns_server;
#endif
              for (const auto& answer : reply->answers)
              {
#if 0
                std::string name;
                for (const auto& label : answer.labels)
                {
                  if (!name.empty())
                    name += '.';
                  name += label;
                }
                if (name != dns_server_tlsa)
                  continue;
#endif
                if (const auto* const tlsa = std::get_if<dns::tlsa_rdata>(&answer.rdata))
                  return *tlsa;
              }
              return util::unexpected(make_error_code(dns::rcode::name_error));
          });
      });
  }();
  if (!tgt)
    throw std::system_error(tgt.error(), "retrieving address of DNS server");

  boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
  SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_2_VERSION);
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
  SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);
#else
  SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_2_VERSION);
#endif
  ctx.load_verify_file("/etc/ssl/certs/ca-certificates.crt");
  ctx.set_verify_mode(boost::asio::ssl::verify_peer);
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
  SSL_CTX_set_keylog_callback(ctx.native_handle(), [] (const SSL* const, const char* const line) noexcept {
      const char* const fname = std::getenv("SSLKEYLOGFILE");
      if (!fname)
        return;
      std::FILE* const f = std::fopen(fname, "a");
      if (!f)
        return;
      std::fputs(line, f);
      std::fputc('\n', f);
      std::fclose(f);
    });
#endif

  SSL_CTX_set_session_cache_mode(ctx.native_handle(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  static constexpr int EX_SERVER_NAME = 7;
  SSL_CTX_set_ex_data(ctx.native_handle(), EX_SERVER_NAME, const_cast<char*>(dns_server));
  const auto session_write_cb = [] (SSL* ssl, SSL_SESSION* session) noexcept {
      const auto dns_server = reinterpret_cast<const char*>(SSL_CTX_get_ex_data(
            SSL_get_SSL_CTX(ssl)
          , EX_SERVER_NAME
          ));
      const auto sfn = "ssl-session-"s + dns_server + ".pem";
      if (const auto f = BIO_new_file(sfn.c_str(), "w"))
      {
        PEM_write_bio_SSL_SESSION(f, session);
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
        if (const char* const fname = std::getenv("SSLKEYLOGFILE"))
        {
          if (const auto kf = BIO_new_file(fname, "a"))
          {
            SSL_SESSION_print_keylog(kf, session);
            BIO_free(kf);
          }
        }
#endif
        BIO_free(f);
      }
      // 0=no we did not retain a reference to this 'session'
      return 0;
    };
  SSL_CTX_sess_set_new_cb(ctx.native_handle(), session_write_cb);

  if (SSL_CTX_dane_enable(ctx.native_handle()) <= 0)
    throw boost::system::system_error(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category(), "context-dane-enable");
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(io, ctx);
  if (tlsa_rec)
  {
    if (SSL_set_tlsext_host_name(socket.native_handle(), dns_server) <= 0)
      throw boost::system::system_error(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category(), "set-tlsext-sni");
    if (SSL_dane_enable(socket.native_handle(), dns_server) <= 0)
      throw boost::system::system_error(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category(), "ssl-dane-enable");
    if (SSL_dane_tlsa_add(
          socket.native_handle()
        , tlsa_rec->cert_usage
        , tlsa_rec->selector
        , tlsa_rec->matching_type
        , tlsa_rec->association_data.data()
        , tlsa_rec->association_data.size()
        ) <= 0)
      throw boost::system::system_error(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category(), "dane-tlsa-add");
  }
  else
  {
    socket.set_verify_callback(boost::asio::ssl::rfc2818_verification(dns_server));
  }

  socket.next_layer().open(tgt->protocol());
  socket.next_layer().set_option(tcp_fastopen_connect(true));

  const auto max_early_data = [&socket, &dns_server] {
      std::uint32_t max_early_data = 0;
      const auto sfn = "ssl-session-"s + dns_server + ".pem";
      if (const auto f = BIO_new_file(sfn.c_str(), "r"))
      {
        auto session = PEM_read_bio_SSL_SESSION(f, nullptr, nullptr, nullptr);
        if (session)
        {
          SSL_set_session(socket.native_handle(), session);
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
          max_early_data = SSL_SESSION_get_max_early_data(session);
#endif
          SSL_SESSION_free(session);
        }
        BIO_free(f);
      }
      return max_early_data;
    }();
  // TODO: do something useful with this
  static_cast<void>(max_early_data);

  auto request = dns::make_question("mortis.eu"sv, dns::rr_type::TXT)
    .map([&buf](auto&& msg) {
        return dns::serialize(
            std::forward<decltype(msg)>(msg)
          , gsl::span<std::uint8_t>(buf + 2, sizeof(buf) - 2)
          )
          .map([&buf] (auto request) {
              // frame size
              buf[0] = static_cast<std::uint8_t>(request.size() >> 8);
              buf[1] = static_cast<std::uint8_t>(request.size() >> 0);
              return gsl::span<std::uint8_t>(buf, request.size() + 2);
          });
      });
  if (!request)
    throw std::system_error(request.error(), "building DNS request");

  boost::asio::posix::stream_descriptor out(io, dup(STDOUT_FILENO));
  socket.next_layer().async_connect(*tgt, [&] (const auto error) {
      if (error)
        throw boost::system::system_error(error, "connect");

      socket.async_handshake(boost::asio::ssl::stream_base::client,
          [&] (const auto error) {
            if (error)
              throw boost::system::system_error(error, "handshake");
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
            session_write_cb(socket.native_handle(), SSL_get0_session(socket.native_handle()));
#endif

            async_write(socket, boost::asio::buffer(request->data(), request->size()),
                [&] (const auto error, const auto) {
                  if (error)
                    throw boost::system::system_error(error, "write");

                  async_read(socket,
                      boost::asio::buffer(buf, 2),
                      [&] (const auto error, const auto bytes_transferred) {
                        if (error)
                          throw boost::system::system_error(error, "read");
                        assert(bytes_transferred == 2);

                        const auto len = static_cast<std::uint16_t>((buf[0] << 8U) | (buf[1] & 0xffU));
                        assert(len < sizeof(buf) - 2);

                        async_read(socket,
                            boost::asio::buffer(buf + 2, len),
                            [&socket, &out, &buf, len] (const auto error, const auto bytes_transferred) {
                              if (error)
                                throw boost::system::system_error(error, "read");
                              assert(bytes_transferred >= len);
                              socket.async_shutdown([] (const auto error) {
                                  if (error
                                   && error != boost::asio::error::eof
                                   && error != boost::asio::ssl::error::stream_truncated)
                                    throw boost::system::system_error(error, "shutdown");
                                });

                                async_write(out, boost::asio::buffer(buf, len + 2),
                                  [] (const auto error, const auto) {
                                    if (error)
                                      throw boost::system::system_error(error, "write(stdout)");
                                  });
                          });
                    });
                });
          });
    });

  io.run();
  io.reset();
}

int main(const int argc, const char** const argv)
{
  boost::asio::io_service io;

  if (argc < 2)
    perform_request(io, "resolver.xs4all.nl");

  for (int arg = 1; arg < argc; ++arg)
    perform_request(io, argv[arg]);
}
