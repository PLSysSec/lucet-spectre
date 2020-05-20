pub fn ensure_linked() {
    lucet_runtime::lucet_internal_ensure_linked();
    lucet_wasi::export_wasi_funcs();
}
