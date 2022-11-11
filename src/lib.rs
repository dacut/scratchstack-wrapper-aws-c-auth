#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
#![allow(clippy::all)]

//! Rust wrapper for the `aws-c-auth` library. For testing purposes only.
//! For interacting with AWS services, use the `aws-sdk-rust` crate instead.

use {
    scratchstack_wrapper_aws_c_cal::aws_ecc_key_pair,
    scratchstack_wrapper_aws_c_common::{
        aws_allocator, aws_array_list, aws_atomic_var, aws_byte_buf, aws_byte_cursor, aws_date_time, aws_hash_table,
        aws_string,
    },
    scratchstack_wrapper_aws_c_http::{aws_http_headers, aws_http_message, aws_http_proxy_options},
    scratchstack_wrapper_aws_c_io::{
        aws_client_bootstrap, aws_input_stream, aws_io_clock_fn, aws_retry_strategy, aws_tls_connection_options,
        aws_tls_ctx,
    },
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests;
