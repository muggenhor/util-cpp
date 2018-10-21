#include <array>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <dns/serializer.hpp>
#include <iostream>
#include <system_error>
#include <type_traits>
#include <utility>

#if defined(TCP_FASTOPEN_CONNECT)
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
#endif

void perform_request(const gsl::span<std::uint8_t> buf, std::string_view name, dns::rr_type rdtype, dns::rr_class rdclass = dns::rr_class::IN)
{
  auto msg = dns::make_question(name, rdtype, rdclass)
    .map([buf](auto&& msg) {
        return dns::serialize(msg, buf);
      });
  if (!msg)
    throw std::system_error(msg.error(), "failed to create DNS request");

  using protocol = boost::asio::ip::tcp;
#if 0
  const protocol::endpoing dst(
      boost::asio::ip::address_v6::loopback()
    , 53
    );
#else
  const protocol::endpoint dst(
      boost::asio::ip::address_v4::from_string("127.0.0.53")
    , 53
    );
#endif

  boost::asio::io_service io;
  protocol::socket sock(io, dst.protocol());

  constexpr bool is_tcp = std::is_same_v<protocol, boost::asio::ip::tcp>;
#if defined(TCP_FASTOPEN_CONNECT)
  if constexpr (is_tcp)
    sock.set_option(tcp_fastopen_connect(true));
#endif

  sock.connect(dst);

  if constexpr (is_tcp)
  {
    const std::uint8_t msg_size[] = {
      static_cast<std::uint8_t>(msg->size() >> 8),
      static_cast<std::uint8_t>(msg->size() >> 0),
    };

    std::array<boost::asio::const_buffer, 2> iov = {{
      { msg_size, sizeof(msg_size) },
      { msg->data(), static_cast<std::size_t>(msg->size()) },
    }};
    sock.send(iov);
  }
  else
  {
    sock.send(boost::asio::buffer(msg->data(), msg->size()));
  }

  auto reply = [&sock, buf] {
      if constexpr (is_tcp)
      {
        if (const auto sz = read(sock, boost::asio::buffer(buf.data(), 2));
            sz != 2)
          throw std::system_error(make_error_code(std::errc::protocol_error), "couldn't read frame size");
        const auto reply_size = static_cast<std::uint16_t>(buf[0] << 8 | buf[1]);
        const auto reply = buf.subspan(0, reply_size + 2);
        if (const auto sz = read(sock, boost::asio::buffer(reply.data() + 2, reply.size() - 2));
            sz != reply_size)
          throw std::system_error(make_error_code(std::errc::protocol_error), "couldn't read full frame");
        return reply;
      }
      else
      {
        const auto sz = sock.read_some(boost::asio::buffer(buf.data(), buf.size()));
        return buf.subspan(0, sz);
      }
    }();

  if constexpr (!is_tcp)
  {
    std::uint8_t reply_size[] = {
      static_cast<std::uint8_t>(reply.size() >> 8),
      static_cast<std::uint8_t>(reply.size() >> 0),
    };
    std::cout.write(reinterpret_cast<const char*>(reply_size), sizeof(reply_size));
  }
  std::cout.write(reinterpret_cast<const char*>(reply.data()), reply.size());
}

int main(int argc, const char** argv)
{
  if (argc < 2)
  {
    std::cerr << "need one argument\n";
    return 2;
  }

  for (int i = 1; i < argc; ++i)
  {
    std::uint8_t buf[4096];
    perform_request(buf, argv[i], dns::rr_type::A, dns::rr_class::IN);
  }
}
