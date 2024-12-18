#ifndef NMOS_CONFIGURATION_HANDLERS_H
#define NMOS_CONFIGURATION_HANDLERS_H

#include <functional>
#include "nmos/control_protocol_typedefs.h"
#include "nmos/control_protocol_handlers.h"
#include "nmos/resources.h"

namespace slog
{
    class base_gate;
}

namespace nmos
{
    namespace experimental
    {
        struct control_protocol_state;
    }
    // This callback is invoked if attempting to modify read only properties when restoring a configuration.
    // This function should modify the Device Model object directly and return a corresponding NcObjectPropertiesSetValidation object
    typedef std::function<web::json::value(nmos::experimental::control_protocol_state& control_protocol_state, nmos::get_control_protocol_class_descriptor_handler get_control_protocol_class_descriptor, const web::json::value& target_role_path, const web::json::value& object_properties_holders, bool recurse, const web::json::value& restore_mode, bool validate)> modify_read_only_config_properties_handler;

    // This callback is invoked if attempting to modify a rebuildable block when restoring a configuration.
    // This function should handle the modification of the Device Model and any corresponding NMOS resources
    // and return correpsonding NcObjectPropertiesSetValidation objects for each object modified/added
    typedef std::function<web::json::value(nmos::experimental::control_protocol_state& control_protocol_state, nmos::get_control_protocol_class_descriptor_handler get_control_protocol_class_descriptor, const web::json::value& target_role_path, const web::json::value& property_values, bool recurse, const web::json::value& restore_mode, bool validate)> modify_rebuildable_block_handler;
}

#endif