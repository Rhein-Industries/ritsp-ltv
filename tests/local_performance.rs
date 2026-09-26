//! Opt-in, local-only measurements. Run with `--ignored --nocapture --test-threads=1`.
use der::{Decode, DecodePem, Encode};
use ritsp_ltv::trust::{build_chain_from_pool, trust_anchor_subjects, TrustStore};
use std::hint::black_box;
use std::time::Instant;
use x509_cert::Certificate;

fn measure(label: &str, iterations: usize, mut work: impl FnMut()) {
    for _ in 0..10 {
        work();
    }
    let mut samples = Vec::new();
    for _ in 0..7 {
        let started = Instant::now();
        for _ in 0..iterations {
            work();
        }
        samples.push(started.elapsed().as_nanos() / iterations as u128);
    }
    samples.sort_unstable();
    println!(
        "{label}: median={} ns/op, range={}..{}, iterations={iterations}, samples=7",
        samples[3], samples[0], samples[6]
    );
}

#[test]
#[ignore = "local performance measurement"]
fn local_validation_workloads() {
    let root = Certificate::from_pem(include_bytes!("fixtures/ca_cert.pem")).unwrap();
    let issuer =
        Certificate::from_pem(include_bytes!("fixtures/intermediate_ca_cert.pem")).unwrap();
    let leaf = Certificate::from_pem(include_bytes!("fixtures/signer_cert.pem")).unwrap();
    let leaf_der = leaf.to_der().unwrap();
    let mut pool = Vec::new();
    let mut store = TrustStore::new();
    for i in 0..128 {
        let mut unrelated = root.clone();
        unrelated.tbs_certificate.subject = format!("CN=Unrelated {i}").parse().unwrap();
        store.add_certificate(unrelated.clone()).unwrap();
        pool.push(unrelated);
    }
    store.add_certificate(root).unwrap();
    pool.push(issuer.clone());
    let subjects = trust_anchor_subjects(&store);
    let chain = [leaf.clone(), issuer];
    measure("certificate_parse", 1000, || {
        black_box(Certificate::from_der(black_box(&leaf_der)).unwrap());
    });
    measure("issuer_lookup_129_anchors", 1000, || {
        black_box(store.find_issuer(black_box(&chain[1])).unwrap());
    });
    measure("chain_build_129_pool", 100, || {
        let built =
            build_chain_from_pool(black_box(&leaf), black_box(&pool), &subjects, None).unwrap();
        assert_eq!(built.len(), 2);
        black_box(built);
    });
    measure("repeated_chain_validation", 100, || {
        black_box(store.verify_chain(black_box(&chain), None).unwrap());
    });
    #[cfg(feature = "tsp")]
    {
        let client = ritsp_ltv::net::hardened_http_client().unwrap();
        measure("http_client_construct", 100, || {
            black_box(ritsp_ltv::net::hardened_http_client().unwrap());
        });
        measure("http_client_clone", 10000, || {
            black_box(client.clone());
        });
    }
}
