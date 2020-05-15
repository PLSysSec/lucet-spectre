fn main() {
    build_c_api_tests();
}

fn build_c_api_tests() {
    cc::Build::new()
        .file("tests/c_api.c")
        .include("include")
        .flag_if_supported("-fcf-protection=full")
        .compile("lucet_runtime_c_api_tests");
}
