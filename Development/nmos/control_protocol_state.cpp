#include "nmos/control_protocol_state.h"

#include "nmos/control_protocol_resource.h" // for nc_object_class_id, nc_block_class_id, nc_worker_class_id, nc_manager_class_id, nc_device_manager_class_id, nc_class_manager_class_id definitions

namespace nmos
{
    namespace experimental
    {
        control_protocol_state::control_protocol_state()
        {
            using web::json::value;

            // setup the core control classes
            control_classes =
            {
                // Control class models
                // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/models/classes/#control-class-models-for-branch-v10-dev
                { details::make_nc_class_id(details::nc_object_class_id), { value::string(U("NcObject class descriptor")), details::nc_object_class_id, U("NcObject"), value::null(), details::make_nc_object_properties(), details::make_nc_object_methods(), details::make_nc_object_events() } },
                { details::make_nc_class_id(details::nc_block_class_id), { value::string(U("NcBlock class descriptor")), details::nc_block_class_id, U("NcBlock"), value::null(), details::make_nc_block_properties(), details::make_nc_block_methods(), details::make_nc_block_events() } },
                { details::make_nc_class_id(details::nc_worker_class_id), { value::string(U("NcWorker class descriptor")), details::nc_worker_class_id, U("NcWorker"), value::null(), details::make_nc_worker_properties(), details::make_nc_worker_methods(), details::make_nc_worker_events() } },
                { details::make_nc_class_id(details::nc_manager_class_id), { value::string(U("NcManager class descriptor")), details::nc_manager_class_id, U("NcManager"), value::null(), details::make_nc_manager_properties(), details::make_nc_manager_methods(), details::make_nc_manager_events() } },
                { details::make_nc_class_id(details::nc_device_manager_class_id), { value::string(U("NcDeviceManager class descriptor")), details::nc_device_manager_class_id, U("NcDeviceManager"), value::string(U("DeviceManager")), details::make_nc_device_manager_properties(), details::make_nc_device_manager_methods(), details::make_nc_device_manager_events() } },
                { details::make_nc_class_id(details::nc_class_manager_class_id), { value::string(U("NcClassManager class descriptor")), details::nc_class_manager_class_id, U("NcClassManager"), value::string(U("ClassManager")), details::make_nc_class_manager_properties(), details::make_nc_class_manager_methods(), details::make_nc_class_manager_events() } },
                // identification beacon model
                // See https://specs.amwa.tv/nmos-control-feature-sets/branches/main/identification/#ncidentbeacon
                { details::make_nc_class_id(details::nc_ident_beacon_class_id), { value::string(U("NcIdentBeacon class descriptor")), details::nc_ident_beacon_class_id, U("NcIdentBeacon"), value::null(), details::make_nc_ident_beacon_properties(), details::make_nc_ident_beacon_methods(), details::make_nc_ident_beacon_events() } },
                // Monitoring
                // See https://specs.amwa.tv/nmos-control-feature-sets/branches/main/monitoring/#ncreceivermonitor
                { details::make_nc_class_id(details::nc_receiver_monitor_class_id), { value::string(U("NcReceiverMonitor class descriptor")), details::nc_receiver_monitor_class_id, U("NcReceiverMonitor"), value::null(), details::make_nc_receiver_monitor_properties(), details::make_nc_receiver_monitor_methods(), details::make_nc_receiver_monitor_events() } },
                { details::make_nc_class_id(details::nc_receiver_monitor_protected_class_id), { value::string(U("NcReceiverMonitorProtected class descriptor")), details::nc_receiver_monitor_protected_class_id, U("NcReceiverMonitorProtected"), value::null(), details::make_nc_receiver_monitor_protected_properties(), details::make_nc_receiver_monitor_protected_methods(), details::make_nc_receiver_monitor_protected_events() } }
            };

            // setup the core datatypes
            datatypes =
            {
                // Dataype models
                // See https://specs.amwa.tv/ms-05-02/branches/v1.0-dev/models/datatypes/#datatype-models-for-branch-v10-dev
                { U("NcClassId"), {details::make_nc_class_id_datatype()} },
                { U("NcOid"), {details::make_nc_oid_datatype()} },
                { U("NcTouchpoint"), {details::make_nc_touchpoint_datatype()} },
                { U("NcElementId"), {details::make_nc_element_id_datatype()} },
                { U("NcPropertyId"), {details::make_nc_property_id_datatype()} },
                { U("NcPropertyConstraints"), {details::make_nc_property_contraints_datatype()} },
                { U("NcMethodResultPropertyValue"), {details::make_nc_method_result_property_value_datatype()} },
                { U("NcMethodStatus"), {details::make_nc_method_status_datatype()} },
                { U("NcMethodResult"), {details::make_nc_method_result_datatype()} },
                { U("NcId"), {details::make_nc_id_datatype()} },
                { U("NcMethodResultId"), {details::make_nc_method_result_id_datatype()} },
                { U("NcMethodResultLength"), {details::make_nc_method_result_length_datatype()} },
                { U("NcPropertyChangeType"), {details::make_nc_property_change_type_datatype()} },
                { U("NcPropertyChangedEventData"), {details::make_nc_property_changed_event_data_datatype()} },
                { U("NcDescriptor"), {details::make_nc_descriptor_datatype()} },
                { U("NcBlockMemberDescriptor"), {details::make_nc_block_member_descriptor_datatype()} },
                { U("NcMethodResultBlockMemberDescriptors"), {details::make_nc_method_result_block_member_descriptors_datatype()} },
                { U("NcVersionCode"), {details::make_nc_version_code_datatype()} },
                { U("NcOrganizationId"), {details::make_nc_organization_id_datatype()} },
                { U("NcUri"), {details::make_nc_uri_datatype()} },
                { U("NcManufacturer"), {details::make_nc_manufacturer_datatype()} },
                { U("NcUuid"), {details::make_nc_uuid_datatype()} },
                { U("NcProduct"), {details::make_nc_product_datatype()} },
                { U("NcDeviceGenericState"), {details::make_nc_device_generic_state_datatype()} },
                { U("NcDeviceOperationalState"), {details::make_nc_device_operational_state_datatype()} },
                { U("NcResetCause"), {details::make_nc_reset_cause_datatype()} },
                { U("NcName"), {details::make_nc_name_datatype()} },
                { U("NcPropertyDescriptor"), {details::make_nc_property_descriptor_datatype()} },
                { U("NcParameterDescriptor"), {details::make_nc_parameter_descriptor_datatype()} },
                { U("NcMethodId"), {details::make_nc_method_id_datatype()} },
                { U("NcMethodDescriptor"), {details::make_nc_method_descriptor_datatype()} },
                { U("NcEventId"), {details::make_nc_event_id_datatype()} },
                { U("NcEventDescriptor"), {details::make_nc_event_descriptor_datatype()} },
                { U("NcClassDescriptor"), {details::make_nc_class_descriptor_datatype()} },
                { U("NcParameterConstraints"), {details::make_nc_parameter_constraints_datatype()} },
                { U("NcDatatypeType"), {details::make_nc_datatype_type_datatype()} },
                { U("NcDatatypeDescriptor"), {details::make_nc_datatype_descriptor_datatype()} },
                { U("NcMethodResultClassDescriptor"), {details::make_nc_method_result_class_descriptor_datatype()} },
                { U("NcMethodResultDatatypeDescriptor"), {details::make_nc_method_result_datatype_descriptor_datatype()} },
                { U("NcMethodResultError"), {details::make_nc_method_result_error_datatype()} },
                { U("NcDatatypeDescriptorEnum"), {details::make_nc_datatype_descriptor_enum_datatype()} },
                { U("NcDatatypeDescriptorPrimitive"), {details::make_nc_datatype_descriptor_primitive_datatype()} },
                { U("NcDatatypeDescriptorStruct"), {details::make_nc_datatype_descriptor_struct_datatype()} },
                { U("NcDatatypeDescriptorTypeDef"), {details::make_nc_datatype_descriptor_type_def_datatype()} },
                { U("NcEnumItemDescriptor"), {details::make_nc_enum_item_descriptor_datatype()} },
                { U("NcFieldDescriptor"), {details::make_nc_field_descriptor_datatype()} },
                { U("NcPropertyConstraintsNumber"), {details::make_nc_property_constraints_number_datatype()} },
                { U("NcPropertyConstraintsString"), {details::make_nc_property_constraints_string_datatype()} },
                { U("NcRegex"), {details::make_nc_regex_datatype()} },
                { U("NcRolePath"), {details::make_nc_role_path_datatype()} },
                { U("NcParameterConstraintsNumber"), {details::make_nc_parameter_constraints_number_datatype()} },
                { U("NcParameterConstraintsString"), {details::make_nc_parameter_constraints_string_datatype()} },
                { U("NcTimeInterval"), {details::make_nc_time_interval_datatype()} },
                { U("NcTouchpointNmos"), {details::make_nc_touchpoint_nmos_datatype()} },
                { U("NcTouchpointNmosChannelMapping"), {details::make_nc_touchpoint_nmos_channel_mapping_datatype()} },
                { U("NcTouchpointResource"), {details::make_nc_touchpoint_resource_datatype()} },
                { U("NcTouchpointResourceNmos"), {details::make_nc_touchpoint_resource_nmos_datatype()} },
                { U("NcTouchpointResourceNmosChannelMapping"), {details::make_nc_touchpoint_resource_nmos_channel_mapping_datatype()} },
                // Monitoring
                // See https://specs.amwa.tv/nmos-control-feature-sets/branches/main/monitoring/#datatypes
                { U("NcConnectionStatus"), {details::make_nc_connection_status_datatype()} },
                { U("NcPayloadStatus"), {details::make_nc_payload_status_datatype()} }
            };
        }
    }
}