#[test]
fn test_init_uninit() {
    use {
        crate::{aws_auth_library_clean_up, aws_auth_library_init},
        scratchstack_wrapper_aws_c_common::aws_default_allocator,
    };

    unsafe {
        aws_auth_library_init(aws_default_allocator());
        aws_auth_library_clean_up();
    }
}
