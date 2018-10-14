#include "dns.hpp"
#include <cstdio>

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
}
