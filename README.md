# Lucet-Spectre &nbsp; [![Build Status]][gh-actions]

This is a fork of the Lucet project (and the wasmtime code generator that is used by Lucet) that adds spectre related hardening to the codegeneration. This work is part of the research paper "Hardening WebAssembly against Spectre". This component is used by https://www.github.com/PLSysSec/lucet-spectre

This fork of Lucet provides some additional flags which use various hardening schemes for code-generation. 

## Attacks
These hardening schemes aim to protect against 3 kinds of attacks.

1) Memory isolation breaks --- Prevent the sandboxed code from using Spectre to read memory outside the sandbox to learn secrets.

2) Sandbox to application poisoning --- One sandbox trains the BTB or PHT while it executes, so that when the application next executes, the victim application accidentally leaks its own secret data.

3) Cross sandbox poisoning --- One sandbox trains the BTB or PHT while it executes, so that when the victim sandbox executes, the victim sandbox accidentally leaks its own secret data.

Memory isolation protections in general are extremely cheap (less than 10%). Protecting against other Sandbox to application poisoning involves Core switching. Cross sandbox protections tend to be quite expensive and may include a BTB flush for certain schemes.

In general the three attacks above are in increasing order of difficulty. Memory isolation breaks are extremely easy to execute, but poisoning attacks are quite challenging.

## Defenses

This fork implements 4 defense schemes.

1) Sfi --- a software only scheme that changes codegen  without the use of lfences to prevent Memory isolation breaks. It uses core switching to prevent Sandbox to application poisoning. It modifies codegen with the blade algorithm (mincut based lfence insertion) and BTB flushing to prevent cross sandbox poisoning.

2) Cet --- this mitigation is meant only for machines with CET support. It uses endbr instructions and lfences and minimal codegen changes to prevent Memory isolation breaks. It uses core switching to prevent Sandbox to application poisoning. It modifies codegen with the blade algorithm (mincut based lfence insertion) to prevent cross sandbox poisoning (does not need BTB flush).

3) Strawman --- this is just a basic hardening scheme that simply places an lfence at the beginning of every basic block to prevent Memory isolation breaks and Cross sandbox poisoning. It uses core switching to prevent Sandbox to application poisoning. This scheme has a lot of overhead.

4) LoadLfence --- As proposed my microsoft and implemented in the VS compiler. Place a load before every lfence to prevent Cross sandbox poisoning. We implement this only as a comparison. This does not offer any way to prevent Memory isolation breaks. We  use core switching to prevent Sandbox to application poisoning.

## New compiler flags

To use the mitigations compile wasm files with lucet with the usual flags. Additionally include the below flags depending on which hardening schemes you want.

Pick the hardening scheme by passing the flag

1) `--spectre-mitigation sfi`
2) `--spectre-mitigation cet`
3) `--spectre-mitigation strawman`
4) `--spectre-mitigation loadlfence` (does not protection from Memory isolation breaks)

By default, this applies protections for all 3 attacks. You can turn off protections or use only part of the protections as well.

- If you only want protections for the Memory isolation breaks, use the flag `--spectre-only-sandbox-isolation`
- If you want protections for Memory isolation breaks and Sandbox to application poisoning. Use the flag `--spectre-no-cross-sbx-attacks`
- If you want protections for Memory isolation breaks and Cross Sandbox poisoning use the flag `--spectre-disable-core-switching`

Some even more fine tuning
- If you want to use SFI protections but do not want BTB flushing use the flag `--spectre-disable-btbflush`
- If you want to use SFI/CET protections but do not want to use the Blade mincut lfence insertion, use `--spectre-pht-mitigation`

--------------------------


[Build Status]: https://github.com/bytecodealliance/lucet/workflows/CI/badge.svg
[gh-actions]: https://github.com/bytecodealliance/lucet/actions?query=workflow%3ACI

**A [Bytecode Alliance][BA] project**

[BA]: https://bytecodealliance.org/

**Lucet is a native WebAssembly compiler and runtime. It is designed
to safely execute untrusted WebAssembly programs inside your application.**

Check out our [announcement post on the Fastly blog][announce-blog].

[announce-blog]: https://www.fastly.com/blog/announcing-lucet-fastly-native-webassembly-compiler-runtime

Lucet uses, and is developed in collaboration with, the Bytecode Alliance's
[Cranelift](http://github.com/bytecodealliance/cranelift) code generator. It powers Fastly's
[Terrarium](https://wasm.fastlylabs.com) platform.

[![asciicast](https://asciinema.org/a/249302.svg)](https://asciinema.org/a/249302)

Lucet's documentation is available at <https://bytecodealliance.github.io/lucet>
([sources](https://github.com/bytecodealliance/lucet/tree/master/docs)).
