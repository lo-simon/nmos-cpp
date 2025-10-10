#include "nmos/server_utils.h"

#include <algorithm>
// cf. preprocessor conditions in nmos::details::make_listener_ssl_context_callback
#if !defined(_WIN32) || !defined(__cplusplus_winrt) || defined(CPPREST_FORCE_HTTP_LISTENER_ASIO)
#ifdef _WIN32
#include <winsock2.h>
#include <mstcpip.h>
#endif
#include <boost/asio.hpp>
#include "boost/asio/ssl/set_cipher_list.hpp"
#include "boost/asio/ssl/use_tmp_ecdh.hpp"
#endif
#include "cpprest/basic_utils.h"
#include "cpprest/details/system_error.h"
#include "cpprest/http_listener.h"
#include "cpprest/ws_listener.h"
#include "nmos/ocsp_state.h"
#include "nmos/ocsp_utils.h"
#include "nmos/slog.h"
#include "nmos/ssl_context_options.h"

// Utility types, constants and functions for implementing NMOS REST API servers
namespace nmos
{
    namespace details
    {
// cf. preprocessor conditions in nmos::make_http_listener_config and nmos::make_websocket_listener_config
#if !defined(_WIN32) || !defined(__cplusplus_winrt) || defined(CPPREST_FORCE_HTTP_LISTENER_ASIO)
        template <typename ExceptionType>
        inline std::function<void(boost::asio::ssl::context&)> make_listener_ssl_context_callback(const nmos::settings& settings, load_server_certificates_handler load_server_certificates, load_dh_param_handler load_dh_param, ocsp_response_handler get_ocsp_response, slog::base_gate& gate)
        {
            if (!load_server_certificates)
            {
                load_server_certificates = make_load_server_certificates_handler(settings, gate);
            }

            if (!load_dh_param)
            {
                load_dh_param = make_load_dh_param_handler(settings, gate);
            }

            auto ocsp_response = std::make_shared<std::vector<uint8_t>>();

            return [&gate, load_server_certificates, load_dh_param, get_ocsp_response, ocsp_response](boost::asio::ssl::context& ctx)
            {
                try
                {
                    ctx.set_options(nmos::details::ssl_context_options);

                    const auto server_certificates = load_server_certificates();

                    if (server_certificates.empty())
                    {
                        throw ExceptionType({}, "Missing server certificates");
                    }

                    for (const auto& server_certificate : server_certificates)
                    {
                        const auto key = utility::us2s(server_certificate.private_key);
                        if (0 == key.size())
                        {
                            throw ExceptionType({}, "Missing private key");
                        }
                        const auto cert_chain = utility::us2s(server_certificate.certificate_chain);
                        if (0 == cert_chain.size())
                        {
                            throw ExceptionType({}, "Missing certificate chain");
                        }
                        ctx.use_private_key(boost::asio::buffer(key.data(), key.size()), boost::asio::ssl::context_base::pem);
                        ctx.use_certificate_chain(boost::asio::buffer(cert_chain.data(), cert_chain.size()));

                        const auto key_algorithm = server_certificate.key_algorithm;
                        if (key_algorithm.empty() || key_algorithm == key_algorithms::ECDSA)
                        {
                            // certificates may not have ECDH parameters, so ignore errors...
                            boost::system::error_code ec;
                            use_tmp_ecdh(ctx, boost::asio::buffer(cert_chain.data(), cert_chain.size()), ec);
                        }
                    }

                    set_cipher_list(ctx, nmos::details::ssl_cipher_list);

                    const auto dh_param = utility::us2s(load_dh_param());
                    if (dh_param.size())
                    {
                        ctx.use_tmp_dh(boost::asio::buffer(dh_param.data(), dh_param.size()));
                    }

                    // set up server certificate status callback when client includes a certificate status request extension in the TLS handshake
                    if (get_ocsp_response)
                    {
                        *ocsp_response = get_ocsp_response();
                        nmos::experimental::set_server_certificate_status_handler(ctx, *ocsp_response.get());
                    }
                }
                catch (const boost::system::system_error& e)
                {
                    throw web::details::from_boost_system_system_error<ExceptionType>(e);
                }
            };
        }

        inline std::function<void(boost::asio::ip::tcp::socket&)> make_listener_tcp_socket_callback(const nmos::settings& settings, slog::base_gate& gate)
        {
            return [&gate, &settings](boost::asio::ip::tcp::socket& sock)
            {
                const int keepalive = nmos::experimental::fields::tcp_keepalive(settings);
                if (0 == setsockopt(sock.native_handle(), SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive)))
                {
                    if (keepalive)
                    {
                        const auto& idle = nmos::experimental::fields::tcp_keepalive_idle(settings);
                        const auto& intvl = nmos::experimental::fields::tcp_keepalive_intvl(settings);
                        const auto& cnt = nmos::experimental::fields::tcp_keepalive_cnt(settings);

                        slog::log<slog::severities::info>(gate, SLOG_FLF) << "Set socket keepalive idle:" << idle << "s, intvl:" << intvl << "s, cnt:" << cnt;

                        // set keepalive parameters
                        // Note: Windows does not support setsockopt(..., TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT) use WSAIoctl(SIO_KEEPALIVE_VALS)
                        // to set keepalive parameters
#ifdef _WIN32
                        tcp_keepalive ka = { 1, idle*1000, intvl*1000 };
                        DWORD bytes = 0;
                        if (SOCKET_ERROR == WSAIoctl(sock.native_handle(), SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes, NULL, NULL))
                        {
                            slog::log<slog::severities::warning>(gate, SLOG_FLF) << "Unable to set socket keepalive error: " << WSAGetLastError();
                        }
#else
                        // The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes
                        if (0 > setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPIDLE, (const char*)&idle, sizeof(idle)))
                        {
                            slog::log<slog::severities::warning>(gate, SLOG_FLF) << "Unable to set socket keepalive idle to " << idle << "sec";
                        }
                        // The time (in seconds) between individual keepalive probes
                        if (0 > setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPINTVL, (const char*)&intvl, sizeof(intvl)))
                        {
                            slog::log<slog::severities::warning>(gate, SLOG_FLF) << "Unable to set socket keepalive intvl to " << intvl << "sec";
                        }
                        // The maximum number of keepalive probes TCP should send before dropping the connection
                        if (0 > setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPCNT, (const char*)&cnt, sizeof(cnt)))
                        {
                            slog::log<slog::severities::warning>(gate, SLOG_FLF) << "Unable to set socket keepalive cnt to " << cnt;
                        }
#endif // _WIN32
                    }
                }
                else
                {
                    slog::log<slog::severities::warning>(gate, SLOG_FLF) << "Unable to set socket keepalive";
                }
            };
        }
#endif
    }

    // construct listener config based on settings
    web::http::experimental::listener::http_listener_config make_http_listener_config(const nmos::settings& settings, load_server_certificates_handler load_server_certificates, load_dh_param_handler load_dh_param, ocsp_response_handler get_ocsp_response, slog::base_gate& gate)
    {
        web::http::experimental::listener::http_listener_config config;
        config.set_backlog(nmos::fields::listen_backlog(settings));
#if !defined(_WIN32) || defined(CPPREST_FORCE_HTTP_LISTENER_ASIO)
        // hmm, hostport_listener::on_accept(...) in http_server_asio.cpp
        // only expects boost::system::system_error to be thrown, so for now
        // don't use web::http::http_exception
        config.set_ssl_context_callback(details::make_listener_ssl_context_callback<boost::system::system_error>(settings, load_server_certificates, load_dh_param, get_ocsp_response, gate));
        config.set_tcp_socket_callback(details::make_listener_tcp_socket_callback(settings, gate));
#endif

        return config;
    }

    // construct listener config based on settings
    web::websockets::experimental::listener::websocket_listener_config make_websocket_listener_config(const nmos::settings& settings, load_server_certificates_handler load_server_certificates, load_dh_param_handler load_dh_param, ocsp_response_handler get_ocsp_response, slog::base_gate& gate)
    {
        web::websockets::experimental::listener::websocket_listener_config config;
        config.set_backlog(nmos::fields::listen_backlog(settings));
#if !defined(_WIN32) || !defined(__cplusplus_winrt)
        config.set_ssl_context_callback(details::make_listener_ssl_context_callback<web::websockets::websocket_exception>(settings, load_server_certificates, load_dh_param, get_ocsp_response, gate));
#endif

        return config;
    }

    namespace experimental
    {
        // map the configured client port to the server port on which to listen
        int server_port(int client_port, const nmos::settings& settings)
        {
            const auto& port_map = nmos::experimental::fields::proxy_map(settings).as_array();
            const auto found = std::find_if(port_map.begin(), port_map.end(), [&](const web::json::value& m)
            {
                return client_port == m.at(U("client_port")).as_integer();
            });
            return port_map.end() != found ? found->at(U("server_port")).as_integer() : client_port;
        }
    }
}
