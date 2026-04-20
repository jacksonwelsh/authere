fn main() {
    // In release builds, compile the UI automatically.
    // In dev builds, expect ui/dist/ to already exist (run `npm run build` manually once).
    if std::env::var("PROFILE").unwrap_or_default() == "release" {
        let status = std::process::Command::new("npm")
            .args(["run", "build"])
            .current_dir("../ui")
            .status()
            .expect("failed to run npm build — is Node installed?");
        assert!(status.success(), "npm run build failed");
    }

    // Re-run this build script if any UI source file changes
    println!("cargo:rerun-if-changed=../ui/src");
    println!("cargo:rerun-if-changed=../ui/package.json");
    println!("cargo:rerun-if-changed=../ui/vite.config.ts");
}
