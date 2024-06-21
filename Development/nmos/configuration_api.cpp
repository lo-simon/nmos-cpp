#include "nmos/configuration_api.h"

#include <boost/algorithm/string/split.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/range/join.hpp>
#include "cpprest/json_validator.h"
#include "nmos/api_utils.h"
#include "nmos/control_protocol_handlers.h"
#include "nmos/control_protocol_methods.h"
#include "nmos/control_protocol_resource.h"
#include "nmos/control_protocol_state.h"
#include "nmos/control_protocol_typedefs.h"
#include "nmos/control_protocol_utils.h"
#include "nmos/is14_versions.h"
#include "nmos/json_schema.h"
#include "nmos/log_manip.h"
#include "nmos/model.h"

namespace nmos
{
    inline web::http::experimental::listener::api_router make_unmounted_configuration_api(node_model& model, get_control_protocol_class_descriptor_handler get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor_handler get_control_protocol_datatype_descriptor, get_control_protocol_method_descriptor_handler get_control_protocol_method_descriptor, get_properties_by_path_handler get_properties_by_path, validate_set_properties_by_path_handler validate_set_properties_by_path, set_properties_by_path_handler set_properties_by_path, control_protocol_property_changed_handler property_changed, slog::base_gate& gate);

    web::http::experimental::listener::api_router make_configuration_api(node_model& model, web::http::experimental::listener::route_handler validate_authorization, get_control_protocol_class_descriptor_handler get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor_handler get_control_protocol_datatype_descriptor, get_control_protocol_method_descriptor_handler get_control_protocol_method_descriptor, get_properties_by_path_handler get_properties_by_path, validate_set_properties_by_path_handler validate_set_properties_by_path, set_properties_by_path_handler set_properties_by_path, control_protocol_property_changed_handler property_changed, slog::base_gate& gate)
    {
        using namespace web::http::experimental::listener::api_router_using_declarations;

        api_router configuration_api;

        configuration_api.support(U("/?"), methods::GET, [](http_request req, http_response res, const string_t&, const route_parameters&)
        {
            set_reply(res, status_codes::OK, nmos::make_sub_routes_body({ U("x-nmos/") }, req, res));
            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/x-nmos/?"), methods::GET, [](http_request req, http_response res, const string_t&, const route_parameters&)
        {
            set_reply(res, status_codes::OK, nmos::make_sub_routes_body({ U("configuration/") }, req, res));
            return pplx::task_from_result(true);
        });

        if (validate_authorization)
        {
            configuration_api.support(U("/x-nmos/") + nmos::patterns::configuration_api.pattern + U("/?"), validate_authorization);
            configuration_api.support(U("/x-nmos/") + nmos::patterns::configuration_api.pattern + U("/.*"), validate_authorization);
        }

        const auto versions = with_read_lock(model.mutex, [&model] { return nmos::is14_versions::from_settings(model.settings); });
        configuration_api.support(U("/x-nmos/") + nmos::patterns::configuration_api.pattern + U("/?"), methods::GET, [versions](http_request req, http_response res, const string_t&, const route_parameters&)
        {
            set_reply(res, status_codes::OK, nmos::make_sub_routes_body(nmos::make_api_version_sub_routes(versions), req, res));
            return pplx::task_from_result(true);
        });

        configuration_api.mount(U("/x-nmos/") + nmos::patterns::configuration_api.pattern + U("/") + nmos::patterns::version.pattern, make_unmounted_configuration_api(model, get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor, get_control_protocol_method_descriptor, get_properties_by_path, validate_set_properties_by_path, set_properties_by_path, property_changed, gate));

        return configuration_api;
    }

    namespace details
    {
        void build_role_paths(const resources& resources, const nmos::resource& resource, const utility::string_t& base_role_path, std::set<utility::string_t>& role_paths)
        {
            if (resource.data.has_field(nmos::fields::nc::members))
            {
                const auto& members = nmos::fields::nc::members(resource.data);

                for (const auto& member : members)
                {
                    const auto role_path = base_role_path + U(".") + nmos::fields::nc::role(member);
                    role_paths.insert(role_path + U("/"));

                    // get members on all NcBlock(s)
                    if (nmos::is_nc_block(nmos::details::parse_nc_class_id(nmos::fields::nc::class_id(member))))
                    {
                        // get resource based on the oid
                        const auto& oid = nmos::fields::nc::oid(member);
                        const auto& found = nmos::find_resource(resources, utility::s2us(std::to_string(oid)));
                        if (resources.end() != found)
                        {
                            build_role_paths(resources, *found, role_path, role_paths);
                        }
                    }
                }
            }
        }

        web::json::value get_nc_block_member_descriptor(const resources& resources, const nmos::resource& parent_nc_block_resource, std::list<utility::string_t>& role_path_segments)
        {
            if (parent_nc_block_resource.data.has_field(nmos::fields::nc::members))
            {
                const auto& members = nmos::fields::nc::members(parent_nc_block_resource.data);

                const auto role_path_segement = role_path_segments.front();
                role_path_segments.pop_front();
                // find the role_path_segment member
                auto member_found = std::find_if(members.begin(), members.end(), [&](const web::json::value& member)
                {
                    return role_path_segement == nmos::fields::nc::role(member);
                });

                if (members.end() != member_found)
                {
                    if (role_path_segments.empty())
                    {
                        // NcBlockMemberDescriptor
                        return *member_found;
                    }

                    // get the role_path_segement member resource
                    if (is_nc_block(nmos::details::parse_nc_class_id(nmos::fields::nc::class_id(*member_found))))
                    {
                        // get resource based on the oid
                        const auto& oid = nmos::fields::nc::oid(*member_found);
                        const auto& found = nmos::find_resource(resources, utility::s2us(std::to_string(oid)));
                        if (resources.end() != found)
                        {
                            return get_nc_block_member_descriptor(resources, *found, role_path_segments);
                        }
                    }
                }
            }
            return web::json::value{};
        }

        resources::const_iterator find_resource(const resources& resources, std::list<utility::string_t>& role_path_segments)
        {
            auto resource = nmos::find_resource(resources, utility::s2us(std::to_string(nmos::root_block_oid)));
            if (resources.end() != resource)
            {
                const auto role = nmos::fields::nc::role(resource->data);
                if (role_path_segments.size() && role == role_path_segments.front())
                {
                    role_path_segments.pop_front();

                    if (role_path_segments.size())
                    {
                        const auto& block_member_descriptor = details::get_nc_block_member_descriptor(resources, *resource, role_path_segments);
                        if (!block_member_descriptor.is_null())
                        {
                            const auto& oid = nmos::fields::nc::oid(block_member_descriptor);
                            const auto& found = nmos::find_resource(resources, utility::s2us(std::to_string(oid)));
                            if (resources.end() != found)
                            {
                                return found;
                            }
                        }
                    }
                    else
                    {
                        return resource;
                    }
                }
            }
            return resources.end();
        }

        resources::const_iterator find_resource(const resources& resources, const utility::string_t& role_path)
        {
            // tokenize the role_path with the '.' delimiter
            std::list<utility::string_t> role_path_segments;
            boost::algorithm::split(role_path_segments, role_path, [](utility::char_t c) { return '.' == c; });

            return find_resource(resources, role_path_segments);
        }

        nc_property_id parse_formatted_property_id(const utility::string_t& property_id)
        {
            // Assume that property_id is in form "<level>p<index>" as validated by the propertyId regular expression pattern
            const utility::string_t::size_type delimiter = property_id.find('p');
            auto level = property_id.substr(0, delimiter);
            auto index = property_id.substr(delimiter + 1);
            return { uint16_t(web::json::value::parse(level).as_integer()), uint16_t(web::json::value::parse(index).as_integer()) };
        }

        // format nc_property_id to the form of "<level>p<index>"
        utility::string_t make_formatted_property_id(const web::json::value& property_descriptor)
        {
            auto property_id = nmos::fields::nc::id(property_descriptor);
            utility::ostringstream_t os;
            os << nmos::fields::nc::level(property_id) << 'p' << nmos::fields::nc::index(property_id);
            return os.str();
        }

        nc_method_id parse_formatted_method_id(const utility::string_t& method_id)
        {
            // Assume that method_id is in form "<level>m<index>" as validated by the methodId regular expression pattern
            const utility::string_t::size_type delimiter = method_id.find('m');
            auto level = method_id.substr(0, delimiter);
            auto index = method_id.substr(delimiter + 1);
            return { uint16_t(web::json::value::parse(level).as_integer()), uint16_t(web::json::value::parse(index).as_integer()) };
        }

        // format nc_method_id to the form of "<level>m<index>"
        utility::string_t make_formatted_method_id(const web::json::value& method_descriptor)
        {
            auto method_id = nmos::fields::nc::id(method_descriptor);
            utility::ostringstream_t os;
            os << nmos::fields::nc::level(method_id) << 'm' << nmos::fields::nc::index(method_id);
            return os.str();
        }

        static const web::json::experimental::json_validator& configurationapi_validator()
        {
            // hmm, could be based on supported API versions from settings, like other APIs' validators?
            static const web::json::experimental::json_validator validator
            {
                nmos::experimental::load_json_schema,
                boost::copy_range<std::vector<web::uri>>(boost::range::join(boost::range::join(boost::range::join(
                    is14_versions::all | boost::adaptors::transformed(experimental::make_configurationapi_method_patch_request_schema_uri),
                    is14_versions::all | boost::adaptors::transformed(experimental::make_configurationapi_property_value_put_request_schema_uri)),
                    is14_versions::all | boost::adaptors::transformed(experimental::make_configurationapi_bulkProperties_validate_request_schema_uri)),
                    is14_versions::all | boost::adaptors::transformed(experimental::make_configurationapi_bulkProperties_set_request_schema_uri)))
            };
            return validator;
        }

        bool parse_recurse_query_parameter(const utility::string_t& query)
        {
            web::json::value arguments = web::json::value_from_query(query);

            if (arguments.has_boolean_field(fields::nc::recurse))
            {
               return fields::nc::recurse(arguments);
            }

            return true;
        }
    }

    inline web::http::experimental::listener::api_router make_unmounted_configuration_api(node_model& model, get_control_protocol_class_descriptor_handler get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor_handler get_control_protocol_datatype_descriptor, get_control_protocol_method_descriptor_handler get_control_protocol_method_descriptor, get_properties_by_path_handler get_properties_by_path, validate_set_properties_by_path_handler validate_set_properties_by_path, set_properties_by_path_handler set_properties_by_path, control_protocol_property_changed_handler property_changed, slog::base_gate& gate_)
    {
        using namespace web::http::experimental::listener::api_router_using_declarations;

        api_router configuration_api;

        // check for supported API version
        const auto versions = with_read_lock(model.mutex, [&model] { return nmos::is14_versions::from_settings(model.settings); });
        configuration_api.support(U(".*"), details::make_api_version_handler(versions, gate_));

        configuration_api.support(U("/?"), methods::GET, [](http_request req, http_response res, const string_t&, const route_parameters&)
        {
            set_reply(res, status_codes::OK, nmos::make_sub_routes_body({ U("rolePaths/") }, req, res));
            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/?"), methods::GET, [&model](http_request req, http_response res, const string_t&, const route_parameters&)
        {
            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            std::set<utility::string_t> role_paths;

            // start at the root block resource
            auto resource = nmos::find_resource(resources, utility::s2us(std::to_string(nmos::root_block_oid)));
            if (resources.end() != resource)
            {
                // add root to role_paths
                const auto role_path = nmos::fields::nc::role(resource->data);
                role_paths.insert(role_path + U("/"));

                // add rest to the role_paths
                details::build_role_paths(resources, *resource, role_path, role_paths);
            }

            set_reply(res, status_codes::OK, nmos::make_sub_routes_body(role_paths, req, res));
            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/?"), methods::GET, [&model, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;
            const auto& resource = details::find_resource(resources, role_path);

            if (resources.end() != resource)
            {
                set_reply(res, status_codes::OK, nmos::make_sub_routes_body({ U("bulkProperties/"), U("descriptor/"), U("methods/"), U("properties/") }, req, res));
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/properties/?"), methods::GET, [&model, get_control_protocol_class_descriptor, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                std::set<utility::string_t> properties_routes;

                auto class_id = nmos::details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data));
                while (!class_id.empty())
                {
                    const auto& control_class = get_control_protocol_class_descriptor(class_id);
                    auto& property_descriptors = control_class.property_descriptors.as_array();

                    auto properties_route = boost::copy_range<std::set<utility::string_t>>(property_descriptors | boost::adaptors::transformed([](const web::json::value& property_descriptor)
                    {
                        return details::make_formatted_property_id(property_descriptor) + U("/");
                    }));

                    properties_routes.insert(properties_route.begin(), properties_route.end());

                    class_id.pop_back();
                }

                set_reply(res, status_codes::OK, nmos::make_sub_routes_body(properties_routes, req, res));
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/methods/?"), methods::GET, [&model, get_control_protocol_class_descriptor, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                std::set<utility::string_t> methods_routes;

                auto class_id = nmos::details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data));
                while (!class_id.empty())
                {
                    const auto& control_class = get_control_protocol_class_descriptor(class_id);
                    auto& method_descriptors = control_class.method_descriptors;

                    auto methods_route = boost::copy_range<std::set<utility::string_t>>(method_descriptors | boost::adaptors::transformed([](const nmos::experimental::method& method)
                    {
                        auto make_method_id = [](const nmos::experimental::method& method)
                        {
                            // method tuple definition described in control_protocol_handlers.h
                            auto& nc_method_descriptor = std::get<0>(method);
                            return details::make_formatted_method_id(nc_method_descriptor);
                        };

                        return make_method_id(method) + U("/");
                    }));

                    methods_routes.insert(methods_route.begin(), methods_route.end());

                    class_id.pop_back();
                }

                set_reply(res, status_codes::OK, nmos::make_sub_routes_body(methods_routes, req, res));
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/descriptor/?"), methods::GET, [&model, get_control_protocol_class_descriptor, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                nc_class_id class_id = nmos::details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data));

                if (!class_id.empty())
                {
                    const auto& control_class = get_control_protocol_class_descriptor(class_id);

                    auto& description = control_class.description;
                    auto& name = control_class.name;
                    auto& fixed_role = control_class.fixed_role;
                    auto property_descriptors = control_class.property_descriptors;
                    auto method_descriptors = value::array();
                    for (const auto& method_descriptor : control_class.method_descriptors) { web::json::push_back(method_descriptors, std::get<0>(method_descriptor)); }
                    auto event_descriptors = control_class.event_descriptors;

                    auto inherited_class_id = class_id;
                    inherited_class_id.pop_back();

                    while (!inherited_class_id.empty())
                    {
                        const auto& inherited_control_class = get_control_protocol_class_descriptor(inherited_class_id);
                        {
                            for (const auto& property_descriptor : inherited_control_class.property_descriptors.as_array()) { web::json::push_back(property_descriptors, property_descriptor); }
                            for (const auto& method_descriptor : inherited_control_class.method_descriptors) { web::json::push_back(method_descriptors, std::get<0>(method_descriptor)); }
                            for (const auto& event_descriptor : inherited_control_class.event_descriptors.as_array()) { web::json::push_back(event_descriptors, event_descriptor); }
                        }
                        inherited_class_id.pop_back();
                    }

                    auto class_descriptor = fixed_role.is_null()
                        ? details::make_nc_class_descriptor(description, class_id, name, property_descriptors, method_descriptors, event_descriptors)
                        : details::make_nc_class_descriptor(description, class_id, name, fixed_role.as_string(), property_descriptors, method_descriptors, event_descriptors);

                    auto method_result = details::make_nc_method_result({ nmos::nc_method_status::ok }, class_descriptor);
                    set_reply(res, status_codes::OK, method_result);
                }
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/properties/") + nmos::patterns::propertyId.pattern + U("/?"), methods::GET, [&model, get_control_protocol_class_descriptor, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto property_id = parameters.at(nmos::patterns::propertyId.name);
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                // find the relevant nc_property_descriptor
                const auto& property_descriptor = find_property_descriptor(details::parse_formatted_property_id(property_id), details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data)), get_control_protocol_class_descriptor);
                if (property_descriptor.is_null())
                {
                    set_error_reply(res, status_codes::NotFound, U("Not Found; ") + property_id);
                }
                else
                {
                    set_reply(res, status_codes::OK, nmos::make_sub_routes_body({ U("descriptor/"), U("value/") }, req, res));
                }
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/properties/") + nmos::patterns::propertyId.pattern + U("/descriptor/?"), methods::GET, [&model, get_control_protocol_class_descriptor, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto property_id = parameters.at(nmos::patterns::propertyId.name);
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                // find the relevant nc_property_descriptor
                const auto& property_descriptor = find_property_descriptor(details::parse_formatted_property_id(property_id), details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data)), get_control_protocol_class_descriptor);
                if (property_descriptor.is_null())
                {
                    set_error_reply(res, status_codes::NotFound, U("Not Found; ") + property_id);
                }
                else
                {
                    auto method_result = details::make_nc_method_result({ nmos::nc_method_status::ok }, property_descriptor);
                    set_reply(res, status_codes::OK, method_result);
                }
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/properties/") + nmos::patterns::propertyId.pattern + U("/value/?"), methods::GET, [&model, get_control_protocol_class_descriptor, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto property_id = parameters.at(nmos::patterns::propertyId.name);
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                // find the relevant nc_property_descriptor
                const auto& property_descriptor = find_property_descriptor(details::parse_formatted_property_id(property_id), details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data)), get_control_protocol_class_descriptor);
                if (property_descriptor.is_null())
                {
                    set_error_reply(res, status_codes::NotFound, U("Not Found; ") + property_id);
                }
                else
                {
                    auto method_result = details::make_nc_method_result({ nmos::fields::nc::is_deprecated(property_descriptor) ? nmos::nc_method_status::property_deprecated : nmos::nc_method_status::ok }, resource->data.at(nmos::fields::nc::name(property_descriptor)));
                    set_reply(res, status_codes::OK, method_result);
                }
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/methods/") + nmos::patterns::methodId.pattern + U("/?"), methods::PATCH, [&model, get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor, get_control_protocol_method_descriptor, property_changed, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            nmos::api_gate gate(gate_, req, parameters);
            return details::extract_json(req, gate).then([&model, req, res, parameters, get_control_protocol_class_descriptor, get_control_protocol_method_descriptor, get_control_protocol_datatype_descriptor, property_changed, gate](value body) mutable
            {
                auto lock = model.write_lock();

                const nmos::api_version version = nmos::parse_api_version(parameters.at(nmos::patterns::version.name));

                // Validate JSON syntax according to the schema
                details::configurationapi_validator().validate(body, experimental::make_configurationapi_method_patch_request_schema_uri(version));

                const auto role_path = parameters.at(nmos::patterns::rolePath.name);
                const auto method_id = parameters.at(nmos::patterns::methodId.name);

                auto& resources = model.control_protocol_resources;
                auto& arguments = nmos::fields::nc::arguments(body);

                const auto& resource = details::find_resource(resources, role_path);
                if (resources.end() != resource)
                {
                    auto method = get_control_protocol_method_descriptor(details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data)), details::parse_formatted_method_id(method_id));
                    auto& nc_method_descriptor = method.first;
                    auto& control_method_handler = method.second;
                    web::http::status_code code{ status_codes::BadRequest };
                    value method_result;

                    if (control_method_handler)
                    {
                        try
                        {
                            // do method arguments constraints validation
                            method_parameters_contraints_validation(arguments, nc_method_descriptor, get_control_protocol_datatype_descriptor);

                            // execute the relevant control method handler, then accumulating up their response to reponses
                            method_result = control_method_handler(resources, *resource, arguments, nmos::fields::nc::is_deprecated(nc_method_descriptor), gate);

                            auto status = nmos::fields::nc::status(method_result);
                            if (nc_method_status::ok == status || nc_method_status::method_deprecated == status) { code = status_codes::OK; }
                            else if (nc_method_status::parameter_error == status) { code = status_codes::BadRequest; }
                            else if (nc_method_status::device_error == status) { code = status_codes::InternalError; }
                            else { code = status_codes::InternalError; }
                        }
                        catch (const nmos::control_protocol_exception& e)
                        {
                            // invalid arguments
                            utility::stringstream_t ss;
                            ss << U("invalid argument: ") << arguments.serialize() << " error: " << e.what();
                            method_result = details::make_nc_method_result_error({ nmos::nc_method_status::parameter_error }, ss.str());

                            code = status_codes::BadRequest;
                        }
                    }
                    else
                    {
                        // unknown methodId
                        utility::stringstream_t ss;
                        ss << U("unsupported method_id: ") << method_id
                            << U(" for control class class_id: ") << resource->data.at(nmos::fields::nc::class_id).serialize();
                        method_result = details::make_nc_method_result_error({ nmos::nc_method_status::method_not_implemented }, ss.str());

                        code = status_codes::NotFound;
                    }
                    set_reply(res, code, method_result);
                }
                else
                {
                    // resource not found for the role path
                    set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
                }

                return true;
            });
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/properties/") + nmos::patterns::propertyId.pattern + U("/value/?"), methods::PUT, [&model, get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor, property_changed, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            nmos::api_gate gate(gate_, req, parameters);
            return details::extract_json(req, gate).then([&model, req, res, parameters, get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor, property_changed, gate](value body) mutable
            {
                auto lock = model.write_lock();

                const nmos::api_version version = nmos::parse_api_version(parameters.at(nmos::patterns::version.name));

                // Validate JSON syntax according to the schema
                details::configurationapi_validator().validate(body, experimental::make_configurationapi_property_value_put_request_schema_uri(version));

                const auto role_path = parameters.at(nmos::patterns::rolePath.name);
                const auto property_id = parameters.at(nmos::patterns::propertyId.name);

                auto& resources = model.control_protocol_resources;

                const auto& resource = details::find_resource(resources, role_path);
                if (resources.end() != resource)
                {
                    // find the relevant nc_property_descriptor
                    const auto& property_descriptor = find_property_descriptor(details::parse_formatted_property_id(property_id), details::parse_nc_class_id(nmos::fields::nc::class_id(resource->data)), get_control_protocol_class_descriptor);
                    if (property_descriptor.is_null())
                    {
                        set_error_reply(res, status_codes::NotFound, U("Not Found; ") + property_id);
                    }
                    else
                    {
                        auto arguments = value_of({
                            { nmos::fields::nc::id, details::make_nc_property_id(details::parse_formatted_property_id(property_id))},
                        });
                        web::json::merge_patch(arguments, body, true);

                        auto result = set(resources, *resource, arguments, false, get_control_protocol_class_descriptor, get_control_protocol_datatype_descriptor, property_changed, gate);

                        auto status = nmos::fields::nc::status(result);
                        auto code = (nc_method_status::ok == status || nc_method_status::property_deprecated == status) ? status_codes::OK : status_codes::InternalError;
                        set_reply(res, code, result);
                    }
                }
                else
                {
                    // resource not found for the role path
                    set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
                }

                return true;
            });
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/bulkProperties/?"), methods::GET, [&model, get_properties_by_path, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();

            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                bool recurse = details::parse_recurse_query_parameter(req.request_uri().query());

                auto result = details::make_nc_method_result_error({ nc_method_status::method_not_implemented }, U("get_properties_by_path not provided"));
                if (get_properties_by_path)
                {
                    result = get_properties_by_path(*resource, recurse);
                }

                auto status = nmos::fields::nc::status(result);
                auto code = (nc_method_status::ok == status || nc_method_status::property_deprecated == status) ? status_codes::OK : status_codes::InternalError;
                set_reply(res, code, result);
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/bulkProperties/?"), methods::PATCH, [&model, validate_set_properties_by_path, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            const nmos::api_version version = nmos::parse_api_version(parameters.at(nmos::patterns::version.name));
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                return details::extract_json(req, gate_).then([res, resources, resource, validate_set_properties_by_path, version, &gate_](value body) mutable
                {
                    // Validate JSON syntax according to the schema
                    details::configurationapi_validator().validate(body, experimental::make_configurationapi_bulkProperties_validate_request_schema_uri(version));

                    bool recurse = nmos::fields::nc::recurse(body);
                    const auto& data_set = nmos::fields::nc::data_set(body);
                    if (!data_set.is_null())
                    {
                        auto result = details::make_nc_method_result_error({ nc_method_status::method_not_implemented }, U("validate_set_properties_by_path not provided"));
                        if (validate_set_properties_by_path)
                        {
                            result = validate_set_properties_by_path(*resource, data_set, recurse);
                        }

                        auto status = nmos::fields::nc::status(result);
                        auto code = (nc_method_status::ok == status || nc_method_status::property_deprecated == status) ? status_codes::OK : status_codes::InternalError;
                        set_reply(res, code, result);
                    }
                    else
                    {
                        set_reply(res, status_codes::BadRequest, nmos::details::make_nc_method_result_error({ nc_method_status::parameter_error }, U("Null dataSet parameter")));
                    }
                    return true;
                });
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        configuration_api.support(U("/rolePaths/") + nmos::patterns::rolePath.pattern + U("/bulkProperties/?"), methods::PUT, [&model, set_properties_by_path, &gate_](http_request req, http_response res, const string_t&, const route_parameters& parameters)
        {
            const auto role_path = parameters.at(nmos::patterns::rolePath.name);

            auto lock = model.read_lock();
            const nmos::api_version version = nmos::parse_api_version(parameters.at(nmos::patterns::version.name));
            auto& resources = model.control_protocol_resources;

            const auto& resource = details::find_resource(resources, role_path);
            if (resources.end() != resource)
            {
                return details::extract_json(req, gate_).then([res, resources, resource, set_properties_by_path, version, &gate_](value body) mutable
                {
                    // Validate JSON syntax according to the schema
                    details::configurationapi_validator().validate(body, experimental::make_configurationapi_bulkProperties_set_request_schema_uri(version));

                    const auto& arguments = nmos::fields::nc::arguments(body);
                    bool recurse = nmos::fields::nc::recurse(arguments);
                    bool allow_incomplete = nmos::fields::nc::allow_incomplete(arguments);
                    const auto& data_set = nmos::fields::nc::data_set(arguments);

                    auto result = details::make_nc_method_result_error({ nc_method_status::method_not_implemented }, U("set_properties_by_path not provided"));
                    if (set_properties_by_path)
                    {
                        result = set_properties_by_path(*resource, data_set, recurse, allow_incomplete);
                    }

                    auto status = nmos::fields::nc::status(result);
                    auto code = (nc_method_status::ok == status || nc_method_status::property_deprecated == status) ? status_codes::OK : status_codes::InternalError;
                    set_reply(res, code, result);

                    return true;
                });
            }
            else
            {
                // resource not found for the role path
                set_error_reply(res, status_codes::NotFound, U("Not Found; ") + role_path);
            }

            return pplx::task_from_result(true);
        });

        return configuration_api;
    }
}