use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn main() {
    embed_i2pd_bundle_manifest();
    tauri_build::build()
}

/// Compute SHA-256 of every file under `i2pd-bundle/` at build time and
/// emit a Rust source manifest (relative-path → hex-digest) that the
/// runtime walks before spawning i2pd. Pinning every file — not just
/// the i2pd executable — closes the dylib-substitution gap (NEW-3 in
/// the dynamic pentest pass): an attacker who replaces `i2pd-bundle/
/// lib/libcrypto.3.dylib` and ad-hoc re-signs the substitute would
/// otherwise be loaded by dyld at i2pd spawn time, since i2pd has no
/// hardened-runtime flag and library validation isn't enforced for it.
/// With the manifest, any byte-level change to *anything* in the
/// bundle — dylibs, certificates, the binary itself — is caught
/// before we hand control to i2pd.
///
/// Scope note for future maintainers: the manifest captures file
/// *contents* only. File permissions / executable bits are not pinned.
/// That's safe today because the bundle is exclusively i2pd + dylibs +
/// `.crt` certificate files — none of which are executed via a shell.
/// If anyone later adds a wrapper script (e.g. an `.sh` helper) to the
/// bundle, the pin must be extended to cover its mode bits, otherwise
/// an attacker could keep the contents intact while flipping +x on a
/// previously-data file. Keep an eye on `walk_bundle` if the bundle
/// shape ever changes.
fn embed_i2pd_bundle_manifest() {
    let bundle_root = Path::new("i2pd-bundle");
    println!("cargo:rerun-if-changed={}", bundle_root.display());

    let mut entries: Vec<(String, String)> = Vec::new();
    let walk_result = if bundle_root.is_dir() {
        walk_bundle(bundle_root, bundle_root, &mut entries)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} is not a directory", bundle_root.display()),
        ))
    };

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set by cargo");
    let manifest_path = PathBuf::from(&out_dir).join("i2pd_bundle_manifest.rs");

    if let Err(e) = walk_result {
        // Same posture as the previous single-binary pin: in release
        // builds, the bundle MUST be present so we can pin. In debug
        // (e.g. `cargo check` before `scripts/bundle-i2pd.sh` runs),
        // we tolerate the gap and emit an empty manifest — the runtime
        // checks then fall through to a debug-only path.
        let profile = std::env::var("PROFILE").unwrap_or_default();
        if profile == "release" {
            panic!(
                "i2pd-bundle/ missing or unreadable ({e}); release builds \
                 require bundle-i2pd.sh to have run first so the per-file \
                 SHA-256 manifest can be embedded"
            );
        }
        println!(
            "cargo:warning=i2pd-bundle/ unreadable ({}); manifest will be empty (debug only)",
            e
        );
        write_manifest(&manifest_path, &[]);
        return;
    }

    // Sort by relative path so the generated source is byte-deterministic
    // across machines — without this, the hash of the binary itself
    // varies depending on directory iteration order.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    if entries.is_empty() {
        let profile = std::env::var("PROFILE").unwrap_or_default();
        if profile == "release" {
            panic!(
                "i2pd-bundle/ exists but contains no files; refusing to ship \
                 a release build with an empty integrity manifest"
            );
        }
        println!("cargo:warning=i2pd-bundle/ contains no files; manifest empty (debug only)");
    }

    write_manifest(&manifest_path, &entries);
}

fn walk_bundle(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Tell cargo to rebuild if any individual file changes — without
        // this, a dylib swap with no surrounding metadata change wouldn't
        // re-trigger build.rs and the manifest would go stale.
        println!("cargo:rerun-if-changed={}", path.display());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            // Skip symlinks defensively — dyld follows them, and we'd
            // hash the symlink target rather than the link, so a swap
            // of the target would not trigger a manifest regen. We
            // expect the bundle to be a flat tree of regular files;
            // anything else is suspect.
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("symlink found in i2pd-bundle: {}", path.display()),
            ));
        }
        if ft.is_dir() {
            walk_bundle(root, &path, out)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let mut h = Sha256::new();
        h.update(&bytes);
        let digest = hex_lower(&h.finalize());
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        out.push((rel, digest));
    }
    Ok(())
}

fn write_manifest(path: &Path, entries: &[(String, String)]) {
    let mut f = std::fs::File::create(path)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    writeln!(
        f,
        "// AUTO-GENERATED by build.rs — do not edit. Walks every file under\n\
         // i2pd-bundle/ and embeds SHA-256 hex digests. Order is sorted by\n\
         // relative path; identical bundles produce a byte-identical manifest.\n\
         pub static I2PD_BUNDLE_MANIFEST: &[(&str, &str)] = &["
    )
    .unwrap();
    for (rel, digest) in entries {
        writeln!(f, "    ({:?}, {:?}),", rel, digest).unwrap();
    }
    writeln!(f, "];").unwrap();
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// Minimal SHA-256 for build.rs — avoids pulling a runtime crate into
// the build graph just for one digest. Public domain reference impl.
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_len += input.len() as u64;
        if self.buffer_len > 0 {
            let need = 64 - self.buffer_len;
            let take = need.min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.compress(&block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        let pad_start = self.buffer_len;
        self.buffer[pad_start] = 0x80;
        if self.buffer_len + 1 > 56 {
            for b in &mut self.buffer[pad_start + 1..] {
                *b = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            for b in &mut self.buffer[..] {
                *b = 0;
            }
        } else {
            for b in &mut self.buffer[pad_start + 1..] {
                *b = 0;
            }
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
