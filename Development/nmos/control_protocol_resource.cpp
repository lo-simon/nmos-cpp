#include "nmos/control_protocol_resource.h"

//#include "nmos/resource.h"
#include "nmos/json_fields.h"

namespace nmos
{
    namespace details
    {
        web::json::value make_nc_method_result(const nc_method_result& method_result)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::status, method_result.status }
            });
        }

        web::json::value make_nc_method_result_error(const nc_method_result& method_result, const utility::string_t& error_message)
        {
            auto result = make_nc_method_result(method_result);
            if (!error_message.empty()) { result[nmos::fields::nc::error_message] = web::json::value::string(error_message); }
            return result;
        }

        web::json::value make_nc_method_result(const nc_method_result& method_result, const web::json::value& value)
        {
            auto result = make_nc_method_result(method_result);
            result[nmos::fields::nc::value] = value;
            return result;
        }

        web::json::value make_control_protocol_error_response(int32_t handle, const nc_method_result& method_result, const utility::string_t& error_message)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::handle, handle },
                { nmos::fields::nc::result, make_nc_method_result_error(method_result, error_message) }
            });
        }

        web::json::value make_control_protocol_response(int32_t handle, const nc_method_result& method_result)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::handle, handle },
                { nmos::fields::nc::result, make_nc_method_result(method_result) }
            });
        }

        web::json::value make_control_protocol_response(int32_t handle, const nc_method_result& method_result, const web::json::value& value)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::handle, handle },
                { nmos::fields::nc::result, make_nc_method_result(method_result, value) }
            });
        }

        web::json::value make_control_protocol_response(int32_t handle, const nc_method_result& method_result, uint32_t value_)
        {
            using web::json::value;

            return make_control_protocol_response(handle, method_result, value(value_));
        }

        // message response
        // See https://specs.amwa.tv/is-12/branches/v1.0-dev/docs/Protocol_messaging.html#command-message-type
        web::json::value make_control_protocol_message_response(nc_message_type::type type, const web::json::value& responses)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::message_type, type },
                { nmos::fields::nc::responses, responses }
            });
        }

        // error message
        // See https://specs.amwa.tv/is-12/branches/v1.0-dev/docs/Protocol_messaging.html#error-messages
        web::json::value make_control_protocol_error_message(const nc_method_result& method_result, const utility::string_t& error_message)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::message_type, nc_message_type::error },
                { nmos::fields::nc::status, method_result.status},
                { nmos::fields::nc::error_message, error_message }
            });
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncclassid
        web::json::value make_nc_class_id(const nc_class_id& class_id)
        {
            using web::json::value;

            auto nc_class_id = value::array();
            for (const auto class_id_item : class_id) { web::json::push_back(nc_class_id, class_id_item); }
            return nc_class_id;
        }

        nc_class_id parse_nc_class_id(const web::json::value& class_id_)
        {
            nc_class_id class_id;
            for (auto& element : class_id_.as_array())
            {
                class_id.push_back(element.as_integer());
            }
            return class_id;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncelementid
        web::json::value make_nc_element_id(uint16_t level, uint16_t index)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::level, level },
                { nmos::fields::nc::index, index }
            });
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#nceventid
        web::json::value make_nc_event_id(uint16_t level, uint16_t index)
        {
            return make_nc_element_id(level, index);
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncmethodid
        web::json::value make_nc_method_id(uint16_t level, uint16_t index)
        {
            return make_nc_element_id(level, index);
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncpropertyid
        web::json::value make_nc_property_id(uint16_t level, uint16_t index)
        {
            return make_nc_element_id(level, index);
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncmanufacturer
        web::json::value make_nc_manufacturer(const utility::string_t& name, const web::json::value& organization_id, const web::json::value& website)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::name, name },
                { nmos::fields::nc::organization_id, organization_id },
                { nmos::fields::nc::website, website }
            });
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncproduct
        // brand_name can be null
        // uuid can be null
        // description can be null
        web::json::value make_nc_product(const utility::string_t& name, const utility::string_t& key, const utility::string_t& revision_level,
            const web::json::value& brand_name, const web::json::value& uuid, const web::json::value& description)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::name, name },
                { nmos::fields::nc::key, key },
                { nmos::fields::nc::revision_level, revision_level },
                { nmos::fields::nc::brand_name, brand_name },
                { nmos::fields::nc::uuid, uuid },
                { nmos::fields::nc::description, description }
            });
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdeviceoperationalstate
        // device_specific_details can be null
        web::json::value make_nc_device_operational_state(nc_device_generic_state::state generic_state, const web::json::value& device_specific_details)
        {
            using web::json::value_of;

            return value_of({
                { nmos::fields::nc::generic_state, generic_state },
                { nmos::fields::nc::device_specific_details, device_specific_details }
            });
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdescriptor
        // description can be null
        web::json::value make_nc_descriptor(const web::json::value& description)
        {
            using web::json::value_of;

            return value_of({ { nmos::fields::nc::description, description } });
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncblockmemberdescriptor
        // description can be null
        // user_label can be null
        web::json::value make_nc_block_member_descriptor(const web::json::value& description, const utility::string_t& role, nc_oid oid, bool constant_oid, const web::json::value& class_id, const web::json::value& user_label, nc_oid owner)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::role] = value::string(role);
            data[nmos::fields::nc::oid] = oid;
            data[nmos::fields::nc::constant_oid] = value::boolean(constant_oid);
            data[nmos::fields::nc::class_id] = class_id;
            data[nmos::fields::nc::user_label] = user_label;
            data[nmos::fields::nc::owner] = owner;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncclassdescriptor
        // description can be null
        // fixedRole can be null
        web::json::value make_nc_class_descriptor(const web::json::value& description, const nc_class_id& class_id, const utility::string_t& name, const web::json::value& fixed_role, const web::json::value& properties, const web::json::value& methods, const web::json::value& events)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::class_id] = make_nc_class_id(class_id);
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::fixed_role] = fixed_role;
            data[nmos::fields::nc::properties] = properties;
            data[nmos::fields::nc::methods] = methods;
            data[nmos::fields::nc::events] = events;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncenumitemdescriptor
        // description can be null
        web::json::value make_nc_enum_item_descriptor(const web::json::value& description, const utility::string_t& name, uint16_t val)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::value] = val;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#nceventdescriptor
        // description can be null
        // id = make_nc_event_id(level, index)
        web::json::value make_nc_event_descriptor(const web::json::value& description, const web::json::value& id, const utility::string_t& name, const utility::string_t& event_datatype, bool is_deprecated)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::id] = id;
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::event_datatype] = value::string(event_datatype);
            data[nmos::fields::nc::is_deprecated] = value::boolean(is_deprecated);

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncfielddescriptor
        // description can be null
        // type_name can be null
        // constraints can be null
        web::json::value make_nc_field_descriptor(const web::json::value& description, const utility::string_t& name, const web::json::value& type_name, bool is_nullable, bool is_sequence, const web::json::value& constraints)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::type_name] = type_name;
            data[nmos::fields::nc::is_nullable] = value::boolean(is_nullable);
            data[nmos::fields::nc::is_sequence] = value::boolean(is_sequence);
            data[nmos::fields::nc::constraints] = constraints;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncmethoddescriptor
        // description can be null
        // id = make_nc_method_id(level, index)
        // sequence<NcParameterDescriptor> parameters
        web::json::value make_nc_method_descriptor(const web::json::value& description, const web::json::value& id, const utility::string_t& name, const utility::string_t& result_datatype, const web::json::value& parameters, bool is_deprecated)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::id] = id;
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::result_datatype] = value::string(result_datatype);
            data[nmos::fields::nc::parameters] = parameters;
            data[nmos::fields::nc::is_deprecated] = value::boolean(is_deprecated);

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncparameterdescriptor
        // description can be null
        // type_name can be null
        web::json::value make_nc_parameter_descriptor(const web::json::value& description, const utility::string_t& name, const web::json::value& type_name, bool is_nullable, bool is_sequence, const web::json::value& constraints)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::type_name] = type_name;
            data[nmos::fields::nc::is_nullable] = value::boolean(is_nullable);
            data[nmos::fields::nc::is_sequence] = value::boolean(is_sequence);
            data[nmos::fields::nc::constraints] = constraints;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncpropertydescriptor
        // description can be null
        // id = make_nc_property_id(level, index);
        // type_name can be null
        // constraints can be null
        web::json::value make_nc_property_descriptor(const web::json::value& description, const web::json::value& id, const utility::string_t& name, const web::json::value& type_name,
            bool is_read_only, bool is_nullable, bool is_sequence, bool is_deprecated, const web::json::value& constraints)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::id] = id;
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::type_name] = type_name;
            data[nmos::fields::nc::is_read_only] = value::boolean(is_read_only);
            data[nmos::fields::nc::is_nullable] = value::boolean(is_nullable);
            data[nmos::fields::nc::is_sequence] = value::boolean(is_sequence);
            data[nmos::fields::nc::is_deprecated] = value::boolean(is_deprecated);
            data[nmos::fields::nc::constraints] = constraints;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdatatypedescriptor
        // description can be null
        // constraints can be null
        web::json::value make_nc_datatype_descriptor(const web::json::value& description, const utility::string_t& name, nc_datatype_type::type type, const web::json::value& constraints)
        {
            using web::json::value;

            auto data = make_nc_descriptor(description);
            data[nmos::fields::nc::name] = value::string(name);
            data[nmos::fields::nc::type] = type;
            data[nmos::fields::nc::constraints] = constraints;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdatatypedescriptorenum
        // description can be null
        // constraints can be null
        // items: sequence<NcEnumItemDescriptor>
        web::json::value make_nc_datatype_descriptor_enum(const web::json::value& description, const utility::string_t& name, const web::json::value& constraints, const web::json::value& items)
        {
            auto data = make_nc_datatype_descriptor(description, name, nc_datatype_type::Enum, constraints);
            data[nmos::fields::nc::items] = items;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdatatypedescriptorprimitive
        // description can be null
        // constraints can be null
        web::json::value make_nc_datatype_descriptor_primitive(const web::json::value& description, const utility::string_t& name, const web::json::value& constraints)
        {
            return make_nc_datatype_descriptor(description, name, nc_datatype_type::Primitive, constraints);
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdatatypedescriptorstruct
        // description can be null
        // constraints can be null
        // fields: sequence<NcFieldDescriptor>
        // parent_type can be null
        web::json::value make_nc_datatype_descriptor_struct(const web::json::value& description, const utility::string_t& name, const web::json::value& constraints, const web::json::value& fields, const web::json::value& parent_type)
        {
            auto data = make_nc_datatype_descriptor(description, name, nc_datatype_type::Struct, constraints);
            data[nmos::fields::nc::fields] = fields;
            data[nmos::fields::nc::parent_type] = parent_type;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdatatypedescriptortypedef
        // description can be null
        // constraints can be null
        web::json::value make_nc_datatype_typedef(const web::json::value& description, const utility::string_t& name, const web::json::value& constraints, const utility::string_t& parent_type, bool is_sequence)
        {
            using web::json::value;

            auto data = make_nc_datatype_descriptor(description, name, nc_datatype_type::Typedef, constraints);
            data[nmos::fields::nc::parent_type] = value::string(parent_type);
            data[nmos::fields::nc::is_sequence] = value::boolean(is_sequence);

            return data;
        }

        web::json::value make_nc_object_properties()
        {
            using web::json::value;

            auto properties = value::array();
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Static value. All instances of the same class will have the same identity value")), make_nc_property_id(1, 1), nmos::fields::nc::class_id, value::string(U("NcClassId")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Object identifier")), make_nc_property_id(1, 2), nmos::fields::nc::oid, value::string(U("NcOid")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("TRUE iff OID is hardwired into device")), make_nc_property_id(1, 3), nmos::fields::nc::constant_oid, value::string(U("NcBoolean")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("OID of containing block. Can only ever be null for the root block")), make_nc_property_id(1, 4), nmos::fields::nc::owner, value::string(U("NcOid")), true, true, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Role of object in the containing block")), make_nc_property_id(1, 5), nmos::fields::nc::role, value::string(U("NcString")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Scribble strip")), make_nc_property_id(1, 6), nmos::fields::nc::user_label, value::string(U("NcString")), false, true, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Touchpoints to other contexts")), make_nc_property_id(1, 7), nmos::fields::nc::touchpoints, value::string(U("NcTouchpoint")), true, true, true, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Runtime property constraints")), make_nc_property_id(1, 8), nmos::fields::nc::runtime_property_constraints, value::string(U("NcPropertyConstraints")), true, true, true, false, value::null()));

            return properties;
        }

        web::json::value make_nc_object_methods()
        {
            using web::json::value;

            auto methods = value::array();
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Get property value")), make_nc_method_id(1, 1), U("Get"), U("NcMethodResultPropertyValue"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property value")), nmos::fields::nc::value, value::null(), true, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Set property value")), make_nc_method_id(1, 2), U("Set"), U("NcMethodResult"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Index of item in the sequence")), nmos::fields::nc::index, value::string(U("NcId")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Get sequence item")), make_nc_method_id(1, 3), U("GetSequenceItem"), U("NcMethodResultPropertyValue"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Index of item in the sequence")), nmos::fields::nc::index, value::string(U("NcId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Value")), nmos::fields::nc::value, value::null(), true, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Set sequence item value")), make_nc_method_id(1, 4), U("SetSequenceItem"), U("NcMethodResult"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Value")), nmos::fields::nc::value, value::null(), true, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Add item to sequence")), make_nc_method_id(1, 5), U("AddSequenceItem"), U("NcMethodResultId"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Index of item in the sequence")), nmos::fields::nc::index, value::string(U("NcId")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Delete sequence item")), make_nc_method_id(1, 6), U("RemoveSequenceItem"), U("NcMethodResult"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Property id")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Get sequence length")), make_nc_method_id(1, 7), U("GetSequenceLength"), U("NcMethodResultLength"), parameters, false));
            }

            return methods;
        }

        web::json::value make_nc_object_events()
        {
            using web::json::value;

            auto events = value::array();
            web::json::push_back(events, make_nc_event_descriptor(value::string(U("Property changed event")), make_nc_event_id(1, 1), U("PropertyChanged"), U("NcPropertyChangedEventData"), false));

            return events;
        }

        web::json::value make_nc_block_properties()
        {
            using web::json::value;

            auto properties = value::array();
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("TRUE if block is functional")), make_nc_property_id(2, 1), nmos::fields::nc::enabled, value::string(U("NcBoolean")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Descriptors of this block's members")), make_nc_property_id(2, 2), nmos::fields::nc::members, value::string(U("NcBlockMemberDescriptor")), true, false, true, false, value::null()));

            return properties;
        }

        web::json::value make_nc_block_methods()
        {
            using web::json::value;

            auto methods = value::array();
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("If recurse is set to true, nested members can be retrieved")), nmos::fields::nc::recurse, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Gets descriptors of members of the block")), make_nc_method_id(2, 1), U("GetMemberDescriptors"), U("NcMethodResultBlockMemberDescriptors"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Relative path to search for (MUST not include the role of the block targeted by oid)")), nmos::fields::nc::path, value::string(U("NcRolePath")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Finds member(s) by path")), make_nc_method_id(2, 2), U("FindMembersByPath"), U("NcMethodResultBlockMemberDescriptors"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Role text to search for")), nmos::fields::nc::role, value::string(U("NcString")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("Signals if the comparison should be case sensitive")), nmos::fields::nc::case_sensitive, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("TRUE to only return exact matches")), nmos::fields::nc::match_whole_string, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("TRUE to search nested blocks")), nmos::fields::nc::recurse, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Finds members with given role name or fragment")), make_nc_method_id(2, 3), U("FindMembersByRole"), U("NcMethodResultBlockMemberDescriptors"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, details::make_nc_parameter_descriptor(value::string(U("Class id to search for")), nmos::fields::nc::class_id, value::string(U("NcClassId")), false, false, value::null()));
                web::json::push_back(parameters, details::make_nc_parameter_descriptor(value::string(U("If TRUE it will also include derived class descriptors")), nmos::fields::nc::include_derived, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(parameters, details::make_nc_parameter_descriptor(value::string(U("TRUE to search nested blocks")), nmos::fields::nc::recurse, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(methods, details::make_nc_method_descriptor(value::string(U("Finds members with given class id")), details::make_nc_method_id(2, 4), U("FindMembersByClassId"), U("NcMethodResultBlockMemberDescriptors"), parameters, false));
            }

            return methods;
        }

        web::json::value make_nc_block_events()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_worker_properties()
        {
            using web::json::value;

            auto properties = value::array();
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("TRUE iff worker is enabled")), make_nc_property_id(2, 1), nmos::fields::nc::enabled, value::string(U("NcBoolean")), false, false, false, false, value::null()));

            return properties;
        }

        web::json::value make_nc_worker_methods()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_worker_events()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_manager_properties()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_manager_methods()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_manager_events()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_device_manager_properties()
        {
            using web::json::value;

            auto properties = value::array();
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Version of MS-05-02 that this device uses")), make_nc_property_id(3, 1), nmos::fields::nc::nc_version, value::string(U("NcVersionCode")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Manufacturer descriptor")), make_nc_property_id(3, 2), nmos::fields::nc::manufacturer, value::string(U("NcManufacturer")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Product descriptor")), make_nc_property_id(3, 3), nmos::fields::nc::product, value::string(U("NcProduct")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Serial number")), make_nc_property_id(3, 4), nmos::fields::nc::serial_number, value::string(U("NcString")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Asset tracking identifier (user specified)")), make_nc_property_id(3, 5), nmos::fields::nc::user_inventory_code, value::string(U("NcString")), false, true, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Name of this device in the application. Instance name, not product name")), make_nc_property_id(3, 6), nmos::fields::nc::device_name, value::string(U("NcString")), false, true, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Role of this device in the application")), make_nc_property_id(3, 7), nmos::fields::nc::device_role, value::string(U("NcString")), false, true, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Device operational state")), make_nc_property_id(3, 8), nmos::fields::nc::operational_state, value::string(U("NcDeviceOperationalState")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Reason for most recent reset")), make_nc_property_id(3, 9), nmos::fields::nc::reset_cause, value::string(U("NcResetCause")), true, false, false, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Arbitrary message from dev to controller")), make_nc_property_id(3, 10), nmos::fields::nc::message, value::string(U("NcString")), true, true, false, false, value::null()));

            return properties;
        }

        web::json::value make_nc_device_manager_methods()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_device_manager_events()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_class_manager_properties()
        {
            using web::json::value;

            auto properties = value::array();
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Descriptions of all control classes in the device (descriptors do not contain inherited elements)")), make_nc_property_id(3, 1), nmos::fields::nc::control_classes, value::string(U("NcClassDescriptor")), true, false, true, false, value::null()));
            web::json::push_back(properties, make_nc_property_descriptor(value::string(U("Descriptions of all data types in the device (descriptors do not contain inherited elements)")), make_nc_property_id(3, 2), nmos::fields::nc::datatypes, value::string(U("NcDatatypeDescriptor")), true, false, true, false, value::null()));

            return properties;
        }

        web::json::value make_nc_class_manager_methods()
        {
            using web::json::value;

            auto methods = value::array();
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("class ID")), nmos::fields::nc::class_id, value::string(U("NcClassId")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("If set the descriptor would contain all inherited elements")), nmos::fields::nc::include_inherited, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Get a single class descriptor")), make_nc_method_id(3, 1), U("GetControlClass"), U("NcMethodResultClassDescriptor"), parameters, false));
            }
            {
                auto parameters = value::array();
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("name of datatype")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
                web::json::push_back(parameters, make_nc_parameter_descriptor(value::string(U("If set the descriptor would contain all inherited elements")), nmos::fields::nc::include_inherited, value::string(U("NcBoolean")), false, false, value::null()));
                web::json::push_back(methods, make_nc_method_descriptor(value::string(U("Get a single datatype descriptor")), make_nc_method_id(3, 2), U("GetDatatype"), U("NcMethodResultDatatypeDescriptor"), parameters, false));
            }

            return methods;
        }

        web::json::value make_nc_class_manager_events()
        {
            using web::json::value;

            return value::array();
        }

        web::json::value make_nc_object_class()
        {
            using web::json::value;

            return make_nc_class_descriptor(value::string(U("NcObject class descriptor")), nc_object_class_id, U("NcObject"), value::null(), make_nc_object_properties(), make_nc_object_methods(), make_nc_object_events());
        }

        web::json::value make_nc_block_class()
        {
            using web::json::value;

            return make_nc_class_descriptor(value::string(U("NcBlock class descriptor")), nc_block_class_id, U("NcBlock"), value::null(), make_nc_block_properties(), make_nc_block_methods(), make_nc_block_events());
        }

        web::json::value make_nc_worker_class()
        {
            using web::json::value;

            return make_nc_class_descriptor(value::string(U("NcWorker class descriptor")), nc_worker_class_id, U("NcWorker"), value::null(), make_nc_worker_properties(), make_nc_worker_methods(), make_nc_worker_events());
        }

        web::json::value make_nc_manager_class()
        {
            using web::json::value;

            return make_nc_class_descriptor(value::string(U("NcManager class descriptor")), nc_manager_class_id, U("NcManager"), value::null(), make_nc_manager_properties(), make_nc_manager_methods(), make_nc_manager_events());
        }

        web::json::value make_nc_device_manager_class()
        {
            using web::json::value;

            return make_nc_class_descriptor(value::string(U("NcDeviceManager class descriptor")), nc_device_manager_class_id, U("NcDeviceManager"), value::string(U("DeviceManager")), make_nc_device_manager_properties(), make_nc_device_manager_methods(), make_nc_device_manager_events());
        }

        web::json::value make_nc_class_manager_class()
        {
            using web::json::value;

            return make_nc_class_descriptor(value::string(U("NcClassManager class descriptor")), nc_class_manager_class_id, U("NcClassManager"), value::string(U("ClassManager")), make_nc_class_manager_properties(), make_nc_class_manager_methods(), make_nc_class_manager_events());
        }

        web::json::value make_nc_class_id_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Sequence of class ID fields")), U("NcClassId"), value::null(), U("NcInt32"), true);
        }

        web::json::value make_nc_oid_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Object id")), U("NcOid"), value::null(), U("NcUint32"), false);
        }

        web::json::value make_nc_touchpoint_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Context namespace")), nmos::fields::nc::context_namespace, value::string(U("NcString")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Base touchpoint class")), U("NcTouchpoint"), value::null(), fields, value::null());
        }

        web::json::value make_nc_element_id_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Level of the element")), nmos::fields::nc::level, value::string(U("NcUint16")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Index of the element")), nmos::fields::nc::index, value::string(U("NcUint16")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Class element id which contains the level and index")), U("NcElementId"), value::null(), fields, value::null());
        }

        web::json::value make_nc_property_id_datatype()
        {
            using web::json::value;

            return make_nc_datatype_descriptor_struct(value::string(U("Property id which contains the level and index")), U("NcPropertyId"), value::null(), value::array(), value::string(U("NcElementId")));
        }

        web::json::value make_nc_property_contraints_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("The id of the property being constrained")), nmos::fields::nc::property_id, value::string(U("NcPropertyId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Optional default value")), nmos::fields::nc::default_value, value::null(), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Property constraints class")), U("NcPropertyConstraints"), value::null(), fields, value::null());
        }

        web::json::value make_nc_method_result_property_value_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Getter method value for the associated property")), nmos::fields::nc::value, value::null(), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Result when invoking the getter method associated with a property")), U("NcMethodResultPropertyValue"), value::null(), fields, value::string(U("NcMethodResult")));
        }

        web::json::value make_nc_method_status_datatype()
        {
            using web::json::value;

            auto items = value::array();
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Method call was successful")), U("Ok"), 200));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Method call was successful but targeted property is deprecated")), U("PropertyDeprecated"), 298));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Method call was successful but method is deprecated")), U("MethodDeprecated"), 299));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Badly-formed command (e.g. the incoming command has invalid message encoding and cannot be parsed by the underlying protocol)")), U("BadCommandFormat"), 400));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Client is not authorized")), U("Unauthorized"), 401));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Command addresses a nonexistent object")), U("BadOid"), 404));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Attempt to change read-only state")), U("Readonly"), 405));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Method call is invalid in current operating context (e.g. attempting to invoke a method when the object is disabled)")), U("InvalidRequest"), 406));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("There is a conflict with the current state of the device")), U("Conflict"), 409));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Something was too big")), U("BufferOverflow"), 413));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Index is outside the available range")), U("IndexOutOfBounds"), 414));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Method parameter does not meet expectations (e.g. attempting to invoke a method with an invalid type for one of its parameters)")), U("ParameterError"), 417));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Addressed object is locked")), U("Locked"), 423));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Internal device error")), U("DeviceError"), 500));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Addressed method is not implemented by the addressed object")), U("MethodNotImplemented"), 501));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Addressed property is not implemented by the addressed object")), U("PropertyNotImplemented"), 502));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("The device is not ready to handle any commands")), U("NotReady"), 503));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Method call did not finish within the allotted time")), U("Timeout"), 504));
            return make_nc_datatype_descriptor_enum(value::string(U("Method invokation status")), U("NcMethodStatus"), value::null(), items);
        }

        web::json::value make_nc_method_result_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Status for the invoked method")), nmos::fields::nc::status, value::string(U("NcMethodStatus")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Base result of the invoked method")), U("NcMethodResult"), value::null(), fields, value::null());
        }

        web::json::value make_nc_id_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Identity handler")), U("NcId"), value::null(), U("NcUint32"), false);
        }

        web::json::value make_nc_method_result_id_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Id result value")), nmos::fields::nc::value, value::string(U("NcId")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Id method result")), U("NcMethodResultId"), value::null(), fields, value::string(U("NcMethodResult")));
        }

        web::json::value make_method_result_length_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Length result value")), nmos::fields::nc::value, value::string(U("NcUint32")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Length method result")), U("NcMethodResultLength"), value::null(), fields, value::string(U("NcMethodResult")));
        }

        web::json::value make_nc_property_change_type_datatype()
        {
            using web::json::value;

            auto items = value::array();
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Current value changed")), U("ValueChanged"), 0));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Sequence item added")), U("SequenceItemAdded"), 1));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Sequence item changed")), U("SequenceItemChanged"), 2));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Sequence item removed")), U("SequenceItemRemoved"), 3));
            return make_nc_datatype_descriptor_enum(value::string(U("Type of property change")), U("NcPropertyChangeType"), value::null(), items);
        }

        web::json::value make_nc_property_changed_event_data_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("The id of the property that changed")), nmos::fields::nc::property_id, value::string(U("NcPropertyId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Information regarding the change type")), nmos::fields::nc::change_type, value::string(U("NcPropertyChangeType")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Property-type specific value")), nmos::fields::nc::value, value::null(), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Index of sequence item if the property is a sequence")), nmos::fields::nc::sequence_item_index, value::string(U("NcId")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Payload of property-changed event")), U("NcPropertyChangedEventData"), value::null(), fields, value::null());
        }

        web::json::value make_nc_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Optional user facing description")), nmos::fields::nc::description, value::string(U("NcString")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Base descriptor")), U("NcDescriptor"), value::null(), fields, value::null());
        }

        web::json::value make_nc_block_member_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Role of member in its containing block")), nmos::fields::nc::role, value::string(U("NcString")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("OID of member")), nmos::fields::nc::oid, value::string(U("NcOid")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff member's OID is hardwired into device")), nmos::fields::nc::constant_oid, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Class ID")), nmos::fields::nc::class_id, value::string(U("NcClassId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("User label")), nmos::fields::nc::user_label, value::string(U("NcString")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Containing block's OID")), nmos::fields::nc::owner, value::string(U("NcOid")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Descriptor which is specific to a block member")), U("NcBlockMemberDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_method_result_block_member_descriptors_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Block member descriptors method result value")), nmos::fields::nc::value, value::string(U("NcBlockMemberDescriptor")), false, true, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Method result containing block member descriptors as the value")), U("NcMethodResultBlockMemberDescriptors"), value::null(), fields, value::string(U("NcMethodResult")));
        }

        web::json::value make_nc_version_code_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Version code in semantic versioning format")), U("NcVersionCode"), value::null(), U("NcString"), false);
        }

        web::json::value make_nc_organization_id_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Unique 24-bit organization id")), U("NcOrganizationId"), value::null(), U("NcInt32"), false);
        }

        web::json::value make_nc_uri_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Uniform resource identifier")), U("NcUri"), value::null(), U("NcString"), false);
        }

        web::json::value make_nc_manufacturer_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Manufacturer's name")), nmos::fields::nc::name, value::string(U("NcString")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("IEEE OUI or CID of manufacturer")), nmos::fields::nc::organization_id, value::string(U("NcOrganizationId")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("URL of the manufacturer's website")), nmos::fields::nc::website, value::string(U("NcUri")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Manufacturer descriptor")), U("NcManufacturer"), value::null(), fields, value::null());
        }

        web::json::value make_nc_uuid_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("UUID")), U("NcUuid"), value::null(), U("NcString"), false);
        }

        web::json::value make_nc_product_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Product name")), nmos::fields::nc::name, value::string(U("NcString")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Manufacturer's unique key to product - model number, SKU, etc")), nmos::fields::nc::key, value::string(U("NcString")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Manufacturer's product revision level code")), nmos::fields::nc::revision_level, value::string(U("NcString")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Brand name under which product is sold")), nmos::fields::nc::brand_name, value::string(U("NcString")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Unique UUID of product (not product instance)")), nmos::fields::nc::uuid, value::string(U("NcUuid")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Text description of product")), nmos::fields::nc::description, value::string(U("NcString")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Product descriptor")), U("NcProduct"), value::null(), fields, value::null());
        }

        web::json::value make_nc_device_generic_state_datatype()
        {
            using web::json::value;

            auto items = value::array();
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Unknown")), U("Unknown"), 0));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Normal operation")), U("NormalOperation"), 1));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Device is initializing")), U("Initializing"), 2));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Device is performing a software or firmware update")), U("Updating"), 3));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Device is experiencing a licensing error")), U("LicensingError"), 4));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Device is experiencing an internal error")), U("InternalError"), 5));
            return make_nc_datatype_descriptor_enum(value::string(U("Device generic operational state")), U("NcDeviceGenericState"), value::null(), items);
        }

        web::json::value make_nc_device_operational_state_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Generic operational state")), nmos::fields::nc::generic_state, value::string(U("NcDeviceGenericState")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Specific device details")), nmos::fields::nc::device_specific_details, value::string(U("NcString")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Device operational state")), U("NcDeviceOperationalState"), value::null(), fields, value::null());
        }

        web::json::value make_nc_reset_cause_datatype()
        {
            using web::json::value;

            auto items = value::array();
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Unknown")), U("Unknown"), 0));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Power on")), U("PowerOn"), 1));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Internal error")), U("InternalError"), 2));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Upgrade")), U("Upgrade"), 3));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Controller request")), U("ControllerRequest"), 4));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Manual request from the front panel")), U("ManualReset"), 5));
            return make_nc_datatype_descriptor_enum(value::string(U("Reset cause enum")), U("NcResetCause"), value::null(), items);
        }

        web::json::value make_nc_name_datatype()
        {
            using web::json::value;

            return make_nc_datatype_typedef(value::string(U("Programmatically significant name, alphanumerics + underscore, no spaces")), U("NcName"), value::null(), U("NcString"), false);
        }

        web::json::value make_nc_property_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Property id with level and index")), nmos::fields::nc::id, value::string(U("NcPropertyId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of property")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of property's datatype. Can only ever be null if the type is any")), nmos::fields::nc::type_name, value::string(U("NcName")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is read-only")), nmos::fields::nc::is_read_only, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is nullable")), nmos::fields::nc::is_nullable, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is a sequence")), nmos::fields::nc::is_sequence, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is marked as deprecated")), nmos::fields::nc::is_deprecated, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Optional constraints on top of the underlying data type")), nmos::fields::nc::constraints, value::string(U("NcParameterConstraints")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Descriptor of a class property")), U("NcPropertyDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_parameter_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of parameter")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of parameter's datatype. Can only ever be null if the type is any")), nmos::fields::nc::type_name, value::string(U("NcName")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is nullable")), nmos::fields::nc::is_nullable, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is a sequence")), nmos::fields::nc::is_sequence, value::string(U("NcBoolean")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Optional constraints on top of the underlying data type")), nmos::fields::nc::constraints, value::string(U("NcParameterConstraints")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Descriptor of a method parameter")), U("NcParameterDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_method_id_datatype()
        {
            using web::json::value;

            return make_nc_datatype_descriptor_struct(value::string(U("Method id which contains the level and index")), U("NcMethodId"), value::null(), value::array(), value::string(U("NcElementId")));
        }

        web::json::value make_nc_method_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Method id with level and index")), nmos::fields::nc::id, value::string(U("NcMethodId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of method")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of method result's datatype")), nmos::fields::nc::result_datatype, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Parameter descriptors if any")), nmos::fields::nc::parameters, value::string(U("NcParameterDescriptor")), false, true, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is marked as deprecated")), nmos::fields::nc::is_deprecated, value::string(U("NcBoolean")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Descriptor of a class method")), U("NcMethodDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_event_id_datatype()
        {
            using web::json::value;

            return make_nc_datatype_descriptor_struct(value::string(U("Event id which contains the level and index")), U("NcEventId"), value::null(), value::array(), value::string(U("NcElementId")));
        }

        web::json::value make_nc_event_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Event id with level and index")), nmos::fields::nc::id, value::string(U("NcEventId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of event")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of event data's datatype")), nmos::fields::nc::event_datatype, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("TRUE iff property is marked as deprecated")), nmos::fields::nc::is_deprecated, value::string(U("NcBoolean")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Descriptor of a class event")), U("NcEventDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_class_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Identity of the class")), nmos::fields::nc::class_id, value::string(U("NcClassId")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Name of the class")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Role if the class has fixed role (manager classes)")), nmos::fields::nc::fixed_role, value::string(U("NcString")), true, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Property descriptors")), nmos::fields::nc::properties, value::string(U("NcPropertyDescriptor")), false, true, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Method descriptors")), nmos::fields::nc::methods, value::string(U("NcMethodDescriptor")), false, true, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Event descriptors")), nmos::fields::nc::events, value::string(U("NcEventDescriptor")), false, true, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Descriptor of a class")), U("NcClassDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_parameter_constraints_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Default value")), nmos::fields::nc::default_value, value::null(), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Abstract parameter constraints class")), U("NcParameterConstraints"), value::null(), fields, value::null());
        }

        web::json::value make_nc_datatype_type_datatype()
        {
            using web::json::value;

            auto items = value::array();
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Primitive datatype")), U("Primitive"), 0));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Simple alias of another datatype")), U("Typedef"), 1));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Data structure")), U("Struct"), 2));
            web::json::push_back(items, make_nc_enum_item_descriptor(value::string(U("Enum datatype")), U("Enum"), 3));
            return make_nc_datatype_descriptor_enum(value::string(U("Datatype type")), U("NcDatatypeType"), value::null(), items);
        }

        web::json::value make_nc_datatype_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Datatype name")), nmos::fields::nc::name, value::string(U("NcName")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Type: Primitive, Typedef, Struct, Enum")), nmos::fields::nc::type, value::string(U("NcDatatypeType")), false, false, value::null()));
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Optional constraints on top of the underlying data type")), nmos::fields::nc::constraints, value::string(U("NcParameterConstraints")), true, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Base datatype descriptor")), U("NcDatatypeDescriptor"), value::null(), fields, value::string(U("NcDescriptor")));
        }

        web::json::value make_nc_method_result_class_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Class descriptor method result value")), nmos::fields::nc::value, value::string(U("NcClassDescriptor")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Method result containing a class descriptor as the value")), U("NcMethodResultClassDescriptor"), value::null(), fields, value::string(U("NcMethodResult")));
        }

        web::json::value make_nc_method_result_datatype_descriptor_datatype()
        {
            using web::json::value;

            auto fields = value::array();
            web::json::push_back(fields, make_nc_field_descriptor(value::string(U("Datatype descriptor method result value")), nmos::fields::nc::value, value::string(U("NcDatatypeDescriptor")), false, false, value::null()));
            return make_nc_datatype_descriptor_struct(value::string(U("Method result containing a datatype descriptor as the value")), U("NcMethodResultDatatypeDescriptor"), value::null(), fields, value::string(U("NcMethodResult")));
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncobject
        web::json::value make_nc_object(const nc_class_id& class_id, nc_oid oid, bool constant_oid, const web::json::value& owner, const utility::string_t& role, const web::json::value& user_label, const web::json::value& touchpoints, const web::json::value& runtime_property_constraints)
        {
            using web::json::value;

            const auto id = utility::conversions::details::to_string_t(oid);
//            auto data = make_resource_core(id, user_label.is_null() ? U("") : user_label.as_string(), {});
            value data;
            data[nmos::fields::id] = value::string(id); // required for nmos::resource
            data[nmos::fields::nc::class_id] = make_nc_class_id(class_id);
            data[nmos::fields::nc::oid] = oid;
            data[nmos::fields::nc::constant_oid] = value::boolean(constant_oid);
            data[nmos::fields::nc::owner] = owner;
            data[nmos::fields::nc::role] = value::string(role);
            data[nmos::fields::nc::user_label] = user_label;
            data[nmos::fields::nc::touchpoints] = touchpoints;
            data[nmos::fields::nc::runtime_property_constraints] = runtime_property_constraints;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncblock
        web::json::value make_nc_block(const nc_class_id& class_id, nc_oid oid, bool constant_oid, const web::json::value& owner, const utility::string_t& role, const web::json::value& user_label, const web::json::value& touchpoints, const web::json::value& runtime_property_constraints, bool enabled, const web::json::value& members)
        {
            using web::json::value;

            auto data = details::make_nc_object(class_id, oid, constant_oid, owner, role, user_label, touchpoints, runtime_property_constraints);
            data[nmos::fields::nc::enabled] = value::boolean(enabled);
            data[nmos::fields::nc::members] = members;

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncmanager
        web::json::value make_nc_manager(const nc_class_id& class_id, nc_oid oid, bool constant_oid, const web::json::value& owner, const utility::string_t& role, const web::json::value& user_label, const web::json::value& touchpoints, const web::json::value& runtime_property_constraints)
        {
            return make_nc_object(class_id, oid, constant_oid, owner, role, user_label, touchpoints, runtime_property_constraints);
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncdevicemanager
        web::json::value make_nc_device_manager(nc_oid oid, nc_oid owner, const web::json::value& user_label, const web::json::value& touchpoints, const web::json::value& runtime_property_constraints,
            const web::json::value& manufacturer, const web::json::value& product, const utility::string_t& serial_number,
            const web::json::value& user_inventory_code, const web::json::value& device_name, const web::json::value& device_role, const web::json::value& operational_state, nc_reset_cause::cause reset_cause)
        {
            using web::json::value;

            auto data = details::make_nc_manager(nc_device_manager_class_id, oid, true, owner, U("DeviceManager"), user_label, touchpoints, runtime_property_constraints);
            data[nmos::fields::nc::nc_version] = value::string(U("v1.0"));
            data[nmos::fields::nc::manufacturer] = manufacturer;
            data[nmos::fields::nc::product] = product;
            data[nmos::fields::nc::serial_number] = value::string(serial_number);
            data[nmos::fields::nc::user_inventory_code] = user_inventory_code;
            data[nmos::fields::nc::device_name] = device_name;
            data[nmos::fields::nc::device_role] = device_role;
            data[nmos::fields::nc::operational_state] = operational_state;
            data[nmos::fields::nc::reset_cause] = reset_cause;
            data[nmos::fields::nc::message] = value::null();

            return data;
        }

        // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/docs/Framework.html#ncclassmanager
        web::json::value make_nc_class_manager(nc_oid oid, nc_oid owner, const web::json::value& user_label)
        {
            using web::json::value;

            auto data = make_nc_manager(nc_class_manager_class_id, oid, true, owner, U("ClassManager"), user_label);

            // minimal control classes
            data[nmos::fields::nc::control_classes] = value::array();
            auto& control_classes = data[nmos::fields::nc::control_classes];

            // NcObject control class
            web::json::push_back(control_classes, make_nc_object_class());
            // NcBlock control class
            web::json::push_back(control_classes, make_nc_block_class());
            // NcWorker control class
            web::json::push_back(control_classes, make_nc_worker_class());
            // NcManager control class
            web::json::push_back(control_classes, make_nc_manager_class());
            // NcDeviceManager control class
            web::json::push_back(control_classes, make_nc_device_manager_class());
            // NcClassManager control class
            web::json::push_back(control_classes, make_nc_class_manager_class());

            // minimal datatypes
            data[nmos::fields::nc::datatypes] = value::array();
            auto& datatypes = data[nmos::fields::nc::datatypes];

            // NcObject datatypes
            // NcClassId
            web::json::push_back(datatypes, make_nc_class_id_datatype());
            // NcOid
            web::json::push_back(datatypes, make_nc_oid_datatype());
            // NcTouchpoint
            web::json::push_back(datatypes, make_nc_touchpoint_datatype());
            // NcElementId
            web::json::push_back(datatypes, make_nc_element_id_datatype());
            // NcPropertyId
            web::json::push_back(datatypes, make_nc_property_id_datatype());
            // NcPropertyConstraints
            web::json::push_back(datatypes, make_nc_property_contraints_datatype());
            // NcMethodResultPropertyValue
            web::json::push_back(datatypes, make_nc_method_result_property_value_datatype());
            // NcMethodStatus
            web::json::push_back(datatypes, make_nc_method_status_datatype());
            // NcMethodResult
            web::json::push_back(datatypes, make_nc_method_result_datatype());
            // NcId
            web::json::push_back(datatypes, make_nc_id_datatype());
            // NcMethodResultId
            web::json::push_back(datatypes, make_nc_method_result_id_datatype());
            // NcMethodResultLength
            web::json::push_back(datatypes, make_method_result_length_datatype());
            // NcPropertyChangeType
            web::json::push_back(datatypes, make_nc_property_change_type_datatype());
            // NcPropertyChangedEventData
            web::json::push_back(datatypes, make_nc_property_changed_event_data_datatype());

            // NcBlock datatypes
            // NcDescriptor
            web::json::push_back(datatypes, make_nc_descriptor_datatype());
            // NcBlockMemberDescriptor
            web::json::push_back(datatypes, make_nc_block_member_descriptor_datatype());
            // NcMethodResultBlockMemberDescriptors
            web::json::push_back(datatypes, make_nc_method_result_block_member_descriptors_datatype());

            // NcWorker has no datatypes

            // NcManager has no datatypes

            // NcDeviceManager datatypes
            // NcVersionCode
            web::json::push_back(datatypes, make_nc_version_code_datatype());
            // NcOrganizationId
            web::json::push_back(datatypes, make_nc_organization_id_datatype());
            // NcUri
            web::json::push_back(datatypes, make_nc_uri_datatype());
            // NcManufacturer
            web::json::push_back(datatypes, make_nc_manufacturer_datatype());
            // NcUuid
            web::json::push_back(datatypes, make_nc_uuid_datatype());
            // NcProduct
            web::json::push_back(datatypes, make_nc_product_datatype());
            // NcDeviceGenericState
            web::json::push_back(datatypes, make_nc_device_generic_state_datatype());
            // NcDeviceOperationalState
            web::json::push_back(datatypes, make_nc_device_operational_state_datatype());
            // NcResetCause
            web::json::push_back(datatypes, make_nc_reset_cause_datatype());

            // NcClassManager datatypes
            // NcName
            web::json::push_back(datatypes, make_nc_name_datatype());
            // NcPropertyDescriptor
            web::json::push_back(datatypes, make_nc_property_descriptor_datatype());
            // NcMethodId
            web::json::push_back(datatypes, make_nc_method_id_datatype());
            // NcParameterDescriptor
            web::json::push_back(datatypes, make_nc_parameter_descriptor_datatype());
            // NcMethodDescriptor
            web::json::push_back(datatypes, make_nc_method_descriptor_datatype());
            // NcEventId
            web::json::push_back(datatypes, make_nc_event_id_datatype());
            // NcEventDescriptor
            web::json::push_back(datatypes, make_nc_event_descriptor_datatype());
            // NcClassDescriptor
            web::json::push_back(datatypes, make_nc_class_descriptor_datatype());
            // NcParameterConstraints
            web::json::push_back(datatypes, make_nc_parameter_constraints_datatype());
            // NcDatatypeType
            web::json::push_back(datatypes, make_nc_datatype_type_datatype());
            // NcDatatypeDescriptor
            web::json::push_back(datatypes, make_nc_datatype_descriptor_datatype());
            // NcMethodResultClassDescriptor
            web::json::push_back(datatypes, make_nc_method_result_class_descriptor_datatype());
            // NcMethodResultDatatypeDescriptor
            web::json::push_back(datatypes, make_nc_method_result_datatype_descriptor_datatype());

            return data;
        }
    }
}
