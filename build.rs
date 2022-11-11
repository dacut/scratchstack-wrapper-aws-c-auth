use {
    bindgen::builder,
    std::{
        env::var,
        fs::{copy, create_dir_all, read_dir},
        path::{Path, PathBuf},
    },
};

const LINK_LIBS: &str = r#"
aws-c-auth
aws-c-sdkutils
aws-c-http
aws-c-compression
aws-c-io
aws-c-cal
s2n
crypto
ssl
"#;
const INCLUDE_PATH: &str = "aws/auth";
const DEP_LIBRARIES: &str = r#"
aws-c-http
aws-c-io
aws-c-sdkutils
aws-c-common
"#;
const FUNCTIONS: &str = r#"
aws_auth_library_init
aws_auth_library_clean_up
aws_imds_client_new
aws_imds_client_acquire
aws_imds_client_release
aws_imds_client_get_resource_async
aws_imds_client_get_ami_id
aws_imds_client_get_ami_launch_index
aws_imds_client_get_ami_manifest_path
aws_imds_client_get_ancestor_ami_ids
aws_imds_client_get_instance_action
aws_imds_client_get_instance_id
aws_imds_client_get_instance_type
aws_imds_client_get_mac_address
aws_imds_client_get_private_ip_address
aws_imds_client_get_availability_zone
aws_imds_client_get_product_codes
aws_imds_client_get_public_key
aws_imds_client_get_ramdisk_id
aws_imds_client_get_reservation_id
aws_imds_client_get_security_groups
aws_imds_client_get_block_device_mapping
aws_imds_client_get_attached_iam_role
aws_imds_client_get_credentials
aws_imds_client_get_iam_profile
aws_imds_client_get_user_data
aws_imds_client_get_instance_signature
aws_imds_client_get_instance_info
aws_credentials_new
aws_credentials_new_anonymous
aws_credentials_new_from_string
aws_credentials_new_ecc
aws_credentials_new_ecc_from_aws_credentials
aws_credentials_acquire
aws_credentials_release
aws_credentials_get_access_key_id
aws_credentials_get_secret_access_key
aws_credentials_get_session_token
aws_credentials_get_expiration_timepoint_seconds
aws_credentials_get_ecc_key_pair
aws_credentials_is_anonymous
aws_ecc_key_pair_new_ecdsa_p256_key_from_aws_credentials
aws_credentials_provider_release
aws_credentials_provider_acquire
aws_credentials_provider_get_credentials
aws_credentials_provider_new_static
aws_credentials_provider_new_anonymous
aws_credentials_provider_new_environment
aws_credentials_provider_new_cached
aws_credentials_provider_new_profile
aws_credentials_provider_new_sts
aws_credentials_provider_new_chain
aws_credentials_provider_new_imds
aws_credentials_provider_new_ecs
aws_credentials_provider_new_x509
aws_credentials_provider_new_sts_web_identity
aws_credentials_provider_new_process
aws_credentials_provider_new_delegate
aws_credentials_provider_new_cognito
aws_credentials_provider_new_cognito_caching
aws_credentials_provider_new_chain_default
aws_signable_destroy
aws_signable_get_property
aws_signable_get_property_list
aws_signable_get_payload_stream
aws_signable_new_http_request
aws_signable_new_chunk
aws_signable_new_trailing_headers
aws_signable_new_canonical_request
aws_signing_algorithm_to_string
aws_validate_aws_signing_config_aws
aws_signing_result_init
aws_signing_result_clean_up
aws_signing_result_set_property
aws_signing_result_get_property
aws_signing_result_append_property_list
aws_signing_result_get_property_list
aws_signing_result_get_property_value_in_property_list
aws_apply_signing_result_to_http_request
aws_sign_request_aws
aws_verify_sigv4a_signing
aws_validate_v4a_authorization_value
aws_trim_padded_sigv4a_signature
"#;
const TYPES: &str = r#"
aws_auth_errors
aws_auth_log_subject
aws_imds_client_shutdown_completed_fn
aws_imds_client_shutdown_options
aws_imds_client_options
aws_imds_client_on_get_resource_callback_fn
aws_imds_iam_profile
aws_imds_instance_info
aws_imds_client_on_get_array_callback_fn
aws_imds_client_on_get_credentials_callback_fn
aws_imds_client_on_get_iam_profile_callback_fn
aws_imds_client_on_get_instance_info_callback_fn
aws_imds_client
aws_on_get_credentials_callback_fn
aws_auth_http_system_vtable
aws_credentials
aws_credentials_provider_get_credentials_fn
aws_credentials_provider_destroy_fn
aws_credentials_provider_vtable
aws_credentials_provider_shutdown_completed_fn
aws_credentials_provider_shutdown_options
aws_credentials_provider
aws_credentials_provider_static_options
aws_credentials_provider_environment_options
aws_credentials_provider_profile_options
aws_credentials_provider_cached_options
aws_credentials_provider_chain_options
aws_imds_protocol_version
aws_credentials_provider_imds_options
aws_credentials_provider_ecs_options
aws_credentials_provider_x509_options
aws_credentials_provider_sts_web_identity_options
aws_credentials_provider_sts_options
aws_credentials_provider_process_options
aws_credentials_provider_chain_default_options
aws_credentials_provider_delegate_get_credentials_fn
aws_credentials_provider_delegate_options
aws_cognito_identity_provider_token_pair
aws_credentials_provider_cognito_options
aws_signable_property_list_pair
aws_signable_get_property_fn
aws_signable_get_property_list_fn
aws_signable_get_payload_stream_fn
aws_signable_destroy_fn
aws_signable_vtable
aws_signable
aws_should_sign_header_fn
aws_signing_config_type
aws_signing_config_base
aws_signing_algorithm
aws_signature_type
aws_signed_body_header_type
aws_signing_config_aws
aws_signing_result_property
aws_signing_result
aws_signing_complete_fn
"#;

const VARS: &str = "
aws_sts_assume_role_default_duration_secs
aws_auth_http_system_vtable
g_aws_http_headers_property_list_name
g_aws_http_query_params_property_list_name
g_aws_http_method_property_name
g_aws_http_uri_property_name
g_aws_signature_property_name
g_aws_previous_signature_property_name
g_aws_canonical_request_property_name
g_aws_signed_body_value_empty_sha256
g_aws_signed_body_value_unsigned_payload
g_aws_signed_body_value_streaming_unsigned_payload_trailer
g_aws_signed_body_value_streaming_aws4_hmac_sha256_payload
g_aws_signed_body_value_streaming_aws4_hmac_sha256_payload_trailer
g_aws_signed_body_value_streaming_aws4_ecdsa_p256_sha256_payload
g_aws_signed_body_value_streaming_aws4_ecdsa_p256_sha256_payload_trailer
g_aws_signed_body_value_streaming_aws4_hmac_sha256_events
g_aws_signing_authorization_header_name
g_aws_signing_authorization_query_param_name
";

fn get_include_dir<P: AsRef<Path>>(dir: P) -> PathBuf {
    let mut result = PathBuf::from(dir.as_ref());

    for folder in INCLUDE_PATH.split('/') {
        result.push(folder);
    }

    result
}

fn main() {
    let root = PathBuf::from(var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(var("OUT_DIR").expect("OUT_DIR not set"));

    let src_include_dir = root.join("include");
    let dst_include_dir = out_dir.join("include");
    let src_lib_include_dir = get_include_dir(&src_include_dir);
    let dst_lib_include_dir = get_include_dir(&dst_include_dir);
    let src_include_dir_str = src_include_dir.to_string_lossy();
    let dst_include_dir_str = dst_include_dir.to_string_lossy();
    let src_lib_include_dir_str = src_lib_include_dir.to_string_lossy();
    let dst_lib_include_dir_str = dst_lib_include_dir.to_string_lossy();

    println!("cargo:include={dst_include_dir_str}");
    println!("cargo:rerun-if-changed=include");
    println!("cargo:rerun-if-env-changed=AWS_CRT_PREFIX");

    if let Ok(aws_crt_prefix) = var("AWS_CRT_PREFIX") {
        println!("cargo:rustc-link-search={aws_crt_prefix}/lib");
    }

    for library_name in LINK_LIBS.split('\n') {
        let library_name = library_name.trim();
        if !library_name.is_empty() {
            println!("cargo:rustc-link-lib={library_name}");
        }
    }

    // Copy include files over
    create_dir_all(&dst_lib_include_dir)
        .unwrap_or_else(|e| panic!("Unable to create directory {dst_lib_include_dir_str}: {e}"));

    let mut builder = builder()
        .clang_arg(format!("-I{src_include_dir_str}"))
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .derive_eq(true)
        .allowlist_recursively(false); // Don't dive into dependent libraries.

    for dep in DEP_LIBRARIES.split('\n') {
        let dep = dep.trim();
        if dep.is_empty() {
            continue;
        }

        let dep = String::from(dep).replace('-', "_").to_uppercase();
        let dep_include_dir =
            PathBuf::from(var(format!("DEP_{dep}_INCLUDE")).unwrap_or_else(|_| panic!("DEP_{dep}_INCLUDE not set")));
        let dep_include_dir_str = dep_include_dir.to_string_lossy();
        builder = builder.clang_arg(format!("-I{dep_include_dir_str}"));
    }

    let mut n_includes = 0;

    for entry in read_dir(&src_lib_include_dir)
        .unwrap_or_else(|e| panic!("Unable to list header files in {src_lib_include_dir_str}: {e}"))
    {
        let entry =
            entry.unwrap_or_else(|e| panic!("Unable to read directory entry in {src_lib_include_dir_str}: {e}"));
        let file_name_string = entry.file_name();
        let src_path = src_lib_include_dir.join(&file_name_string);
        let src_path_str = src_path.to_string_lossy();
        let dst_path = dst_lib_include_dir.join(&file_name_string);

        if entry.file_type().unwrap_or_else(|e| panic!("Unable to read file type of {src_path_str}: {e}")).is_file() {
            // Only include header files ending with .h; ignore .inl.
            let file_name_utf8 = file_name_string.to_str().expect("Unable to convert file name to UTF-8");
            if file_name_utf8.ends_with(".h") {
                builder = builder.header(src_path_str.to_string());
                n_includes += 1;
            }

            // Copy all files to the output directory.
            copy(&src_path, &dst_path).unwrap_or_else(|e| {
                panic!(
                    "Failed to copy from {src_path_str} to {dst_path_str}: {e}",
                    dst_path_str = dst_path.to_string_lossy()
                )
            });
        }
    }

    if n_includes == 0 {
        panic!("No header files found in {src_lib_include_dir_str}");
    }

    for function_pattern in FUNCTIONS.split('\n') {
        let function_pattern = function_pattern.trim();
        if !function_pattern.is_empty() {
            builder = builder.allowlist_function(function_pattern);
        }
    }

    for type_pattern in TYPES.split('\n') {
        let type_pattern = type_pattern.trim();
        if !type_pattern.is_empty() {
            builder = builder.allowlist_type(type_pattern);
        }
    }

    for var_pattern in VARS.split('\n') {
        let var_pattern = var_pattern.trim();
        if !var_pattern.is_empty() {
            builder = builder.allowlist_var(var_pattern);
        }
    }

    let bindings_filename = out_dir.join("bindings.rs");
    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings.write_to_file(&bindings_filename).unwrap_or_else(|e| {
        panic!(
            "Failed to write bindings to {bindings_filename_str}: {e}",
            bindings_filename_str = bindings_filename.to_string_lossy()
        )
    });

    if cfg!(any(target_os = "ios", target_os = "macos")) {
        println!("cargo:rustc-link-arg=-framework");
        println!("cargo:rustc-link-arg=CoreFoundation");
    }
}
