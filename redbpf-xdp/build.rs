use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

const XDP_HEADER: &str = "./include/xdp.h";

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_unsafe)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name = name,
        bindings = bindings
    )
}

fn main() {
    println!("cargo:rerun-if-changed={}", XDP_HEADER);

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let types = ["pt_regs", "s32", "bpf_.*"];
    let vars = ["BPF_.*"];
    let xdp_types = [
        "ethhdr",
        "iphdr",
        "ipv6hdr",
        "icmphdr",
        "icmp6hdr",
        "tcphdr",
        "udphdr",
        "inet_sock",
        "sockaddr",
        "sockaddr_in",
        "in_addr",
        "in6_addr",
    ];
    let xdp_vars = ["ETH_.*", "IPPROTO_.*", "ICMP_.*", "ICMPV6_.*", "AF_.*"];

    let mut builder = cargo_bpf_lib::bindgen::builder()
        .header(XDP_HEADER)
        .derive_debug(true);

    for ty in types.iter().chain(xdp_types.iter()) {
        builder = builder.whitelist_type(ty);
    }

    for var in vars.iter().chain(xdp_vars.iter()) {
        builder = builder.whitelist_var(var);
    }

    builder = builder.opaque_type("xregs_state");

    let bindings = builder
        .generate()
        .expect("failed to generate bindings")
        .to_string();

    create_module(out_dir.join("gen_bindings.rs"), "gen_bindings", &bindings).unwrap();
}
