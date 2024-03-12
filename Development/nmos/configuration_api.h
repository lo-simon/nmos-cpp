#ifndef NMOS_CONFIGURATION_API_H
#define NMOS_CONFIGURATION_API_H

#include "cpprest/api_router.h"

namespace slog
{
    class base_gate;
}

// Configuration API implementation
// See https://specs.amwa.tv/is-device-configuration/branches/publish-CR/docs/API_requests.html
namespace nmos
{
    struct node_model;

    web::http::experimental::listener::api_router make_configuration_api(nmos::node_model& model, web::http::experimental::listener::route_handler validate_authorization, slog::base_gate& gate);
}

#endif