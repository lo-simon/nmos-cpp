#ifndef NMOS_CONFIGURATION_API_H
#define NMOS_CONFIGURATION_API_H

#include "cpprest/api_router.h"
#include "nmos/control_protocol_handlers.h"

namespace slog
{
    class base_gate;
}

// Configuration API implementation
// See https://specs.amwa.tv/is-device-configuration/branches/publish-CR/docs/API_requests.html
namespace nmos
{
    struct node_model;

    web::http::experimental::listener::api_router make_configuration_api(nmos::node_model& model, web::http::experimental::listener::route_handler validate_authorization, get_control_protocol_class_descriptor_handler get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor_handler get_control_protocol_datatype_descriptor, get_control_protocol_method_descriptor_handler get_control_protocol_method_descriptor, get_properties_by_path_handler get_properties_by_path, validate_set_properties_by_path_handler validate_set_properties_by_path, set_properties_by_path_handler set_properties_by_path, control_protocol_property_changed_handler property_changed, slog::base_gate& gate);
}

#endif