//! Manual definition of the stack probe.
//!
//! Rust currently fails to reexport symbols in dynamic libraries. This means that the old way of
//! including an assembly stack probe in the runtime does not work when embedding in C.
//!
//! There is an [issue](https://github.com/rust-lang/rust/issues/36342) tracking this, but until
//! it's closed we are taking the approach of including the stack probe in every Lucet module, and
//! adding custom entries for it into the trap table, so that stack overflows in the probe will be
//! treated like any other guest trap.

use crate::decls::ModuleDecls;
use crate::module::UniqueFuncIndex;
use cranelift_codegen::binemit::TrapSink;
use cranelift_codegen::ir;
use cranelift_codegen::ir::{types, AbiParam, Signature};
use cranelift_codegen::isa::CallConv;
use cranelift_faerie::traps::{FaerieTrapManifest, FaerieTrapSink};
use cranelift_faerie::FaerieProduct;
use cranelift_module::{Backend as ClifBackend, Linkage, Module as ClifModule};
use cranelift_spectre::settings::get_spectre_settings;
use faerie::Decl;
use failure::Error;
use std::convert::TryFrom;

/// Stack probe symbol name
pub const STACK_PROBE_SYM: &'static str = "lucet_probestack";

/// The binary of the stack probe.
// pub(crate) const STACK_PROBE_BINARY: &'static [u8] = &[
//     // 49 89 c3                     mov    %rax,%r11
//     // 48 81 ec 00 10 00 00         sub    $0x1000,%rsp
//     // 48 85 64 24 08               test   %rsp,0x8(%rsp)
//     // 49 81 eb 00 10 00 00         sub    $0x1000,%r11
//     // 49 81 fb 00 10 00 00         cmp    $0x1000,%r11
//     // 77 e4                        ja     4dfd3 <lucet_probestack+0x3>
//     // 4c 29 dc                     sub    %r11,%rsp
//     // 48 85 64 24 08               test   %rsp,0x8(%rsp)
//     // 48 01 c4                     add    %rax,%rsp
//     // c3                           retq
//     0x49, 0x89, 0xc3, 0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00, 0x48, 0x85, 0x64, 0x24, 0x08, 0x49,
//     0x81, 0xeb, 0x00, 0x10, 0x00, 0x00, 0x49, 0x81, 0xfb, 0x00, 0x10, 0x00, 0x00, 0x77, 0xe4, 0x4c,
//     0x29, 0xdc, 0x48, 0x85, 0x64, 0x24, 0x08, 0x48, 0x01, 0xc4, 0xc3,
// ];

pub fn get_stack_probe_binary() -> Vec<u8> {
    // 49 89 c3                     mov    %rax,%r11
    // 48 81 ec 00 10 00 00         sub    $0x1000,%rsp
    // 48 85 64 24 08               test   %rsp,0x8(%rsp)
    // 49 81 eb 00 10 00 00         sub    $0x1000,%r11
    // 49 81 fb 00 10 00 00         cmp    $0x1000,%r11
    // <... appropriate nop padding for alignment ...>
    // 77 e4                        ja     4dfd3 <lucet_probestack+0x3>
    // 4c 29 dc                     sub    %r11,%rsp
    // 48 85 64 24 08               test   %rsp,0x8(%rsp)
    // 48 01 c4                     add    %rax,%rsp
    // c3                           retq
    let mut ret = vec![
        0x49, 0x89, 0xc3, 0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00, 0x48, 0x85, 0x64, 0x24, 0x08, 0x49,
        0x81, 0xeb, 0x00, 0x10, 0x00, 0x00, 0x49, 0x81, 0xfb, 0x00, 0x10, 0x00, 0x00,
    ];

    let spectre_settings = get_spectre_settings();
    let br_padding = if spectre_settings.enable {
        // Offset is now 29
        let offset = 29;
        let alignment = spectre_settings.alignment;
        let alignment_block = spectre_settings.alignment_block;
        let block_zero_offset_padding = alignment_block - (offset % alignment_block);
        let padding = (block_zero_offset_padding + alignment) % alignment_block;

        for _i in 0..padding {
            ret.push(0x90);
        }

        u8::try_from(padding).unwrap()
    } else {
        0
    };

    // jump prefix
    ret.push(0x77);
    ret.push(0xe4 - br_padding);

    //remaining
    let mut remaining = vec![
        0x4c,
        0x29, 0xdc, 0x48, 0x85, 0x64, 0x24, 0x08, 0x48, 0x01, 0xc4, 0xc3,
    ];
    ret.append(&mut remaining);

    if spectre_settings.enable {
        let alignment_block = spectre_settings.alignment_block;
        let func_len = u32::try_from(ret.len()).unwrap();
        let func_padding = alignment_block - (func_len % alignment_block);
        for _i in 0..func_padding {
            ret.push(0x90);
        }
    }

    // if spectre_settings.enable {
    //     ret.append(&mut get_retpoline_binary())
    // }

    return ret;
}

pub fn get_retpoline_binary() -> Vec<u8> {
    //                            .align 16;
    //                            retpoline_rax_trampoline:
    //  e8 0b 00 00 00                 call set_up_target;
    //                            capture_spec:
    //  f3 90 0f ae e8                 pause; lfence
    //  eb f9                          jmp capture_spec;
    //  0f 1f 40 00               .align 16;
    //                            set_up_target:
    //  4c 89 1c 24                    mov %r11, (%rsp);
    //  c3                             ret;


    let mut ret = vec![ 0xe8, 0x0b, 0x00, 0x00, 0x00, 0xf3, 0x90, 0x0f, 0xae, 
        0xe8, 0xeb, 0xf9, 0x0f, 0x1f, 0x40, 0x00, 0x4c, 0x89, 0x1c, 0x24, 0xc3, ];

    let spectre_settings = get_spectre_settings();

    let alignment_block = spectre_settings.alignment_block;
    let func_len = u32::try_from(ret.len()).unwrap();
    let func_padding = alignment_block - (func_len % alignment_block);
    for _i in 0..func_padding {
        ret.push(0x90);
    }

    return ret;
}

pub fn declare_metadata<'a, B: ClifBackend>(
    decls: &mut ModuleDecls<'a>,
    clif_module: &mut ClifModule<B>,
) -> Result<UniqueFuncIndex, Error> {
    Ok(decls
        .declare_new_function(
            clif_module,
            STACK_PROBE_SYM.to_string(),
            Linkage::Local,
            Signature {
                params: vec![],
                returns: vec![AbiParam::new(types::I32)],
                call_conv: CallConv::SystemV, // the stack probe function is very specific to x86_64, and possibly to SystemV ABI platforms?
            },
        )
        .unwrap())
}

pub fn declare_and_define(product: &mut FaerieProduct) -> Result<(), Error> {
    product.artifact.declare_with(
        STACK_PROBE_SYM,
        Decl::function(),
        get_stack_probe_binary(),
    )?;
    add_sink(
        product
            .trap_manifest
            .as_mut()
            .expect("trap manifest is present"),
    );
    Ok(())
}

fn find_test_rsp(buffer: &Vec<u8>) -> Vec<usize> {
    let mut ret = vec![];
    let to_find = vec![0x48, 0x85, 0x64, 0x24, 0x08];
    let end = buffer.len() - to_find.len();
    
    'outer: for i in 0..end {
        for j in 0..to_find.len() {
            if buffer[i + j] != to_find[j]{
                continue 'outer;
            }
        }

        ret.push(i);
    }

    return ret;
}
fn add_sink(manifest: &mut FaerieTrapManifest) {
    let stack_probe_binary = get_stack_probe_binary();
    let mut stack_probe_trap_sink =
        FaerieTrapSink::new(STACK_PROBE_SYM, stack_probe_binary.len() as u32);

    let indexes = find_test_rsp(&stack_probe_binary);

    for i in indexes{
        stack_probe_trap_sink.trap(
            u32::try_from(i).unwrap(), /* test %rsp,0x8(%rsp) */
            ir::SourceLoc::default(),
            ir::TrapCode::StackOverflow,
        );
    }
    manifest.add_sink(stack_probe_trap_sink);
}
