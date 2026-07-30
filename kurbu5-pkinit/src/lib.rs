mod client_plugin;
mod kdc_plugin;
mod o2k;
mod principal;
mod profile;
mod trace;

use client_plugin::PkinitClient;
use kdc_plugin::{PkinitCertauth, PkinitKdc};

kurbu5_rs::initvt_plugin!(
    clpreauth_pkinit_initvt,
    1,
    PkinitClient,
    kurbu5_rs::clpreauth::glue::make_clpreauth_vtable
);

kurbu5_rs::initvt_plugin!(
    kdcpreauth_pkinit_initvt,
    1,
    PkinitKdc,
    kurbu5_rs::kdcpreauth::glue::make_kdcpreauth_vtable
);

kurbu5_rs::initvt_plugin!(
    certauth_pkinit_initvt,
    1,
    PkinitCertauth,
    kurbu5_rs::certauth::glue::make_certauth_vtable
);
