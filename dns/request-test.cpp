#include <dns/serializer.hpp>
#include <iostream>
#include <utility>

#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <system_error>
#include <sys/types.h>
#include <sys/socket.h>

void perform_request(const gsl::span<std::uint8_t> buf, std::string_view name, dns::rr_type rdtype, dns::rr_class rdclass = dns::rr_class::IN)
{
  auto msg = dns::make_question(name, rdtype, rdclass)
    .map([buf](auto&& msg) {
        return dns::serialize(msg, buf);
      });
  if (!msg)
    throw std::system_error(msg.error(), "failed to create DNS request");

  const sockaddr_in dst = {
    AF_INET,
    htons(53),
    inet_addr("127.0.0.53"),
  };

  constexpr bool is_tcp = true;
  const int fd = socket(AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (fd == -1)
    throw std::system_error(errno, std::system_category(), "creating UDP socket");

  if constexpr (is_tcp)
  {
    const int optval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &optval, sizeof(optval)) == -1)
      throw std::system_error(errno, std::system_category(), "enabling TCP Fast Open");
  }

  if (connect(fd, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) == -1)
    throw std::system_error(errno, std::system_category(), "connecting to recursive DNS resolver");

  if constexpr (is_tcp)
  {
    const std::uint8_t msg_size[] = {
      static_cast<std::uint8_t>(msg->size() >> 8),
      static_cast<std::uint8_t>(msg->size() >> 0),
    };
    const iovec iov[] = {
      { const_cast<std::uint8_t*>(msg_size), sizeof(msg_size) },
      { const_cast<std::uint8_t*>(msg->data()), static_cast<size_t>(msg->size()) },
    };
    const msghdr hdr {
      const_cast<sockaddr_in*>(&dst),
      sizeof(dst),
      const_cast<iovec*>(iov),
      sizeof(iov) / sizeof(iov[0]),
    };
    if (sendmsg(fd, &hdr, 0) == -1)
      throw std::system_error(errno, std::system_category(), "sending DNS request");
  }
  else
  {
    if (send(fd, msg->data(), msg->size(), 0) == -1)
      throw std::system_error(errno, std::system_category(), "sending DNS request");
  }

  auto reply = [fd, buf, dst] {
      const auto sz = recv(fd, buf.data(), buf.size(), 0);
      if (sz == -1)
        throw std::system_error(errno, std::system_category(), "receiving UDP message");
      return buf.subspan(0, sz);
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
