fn main() {
    tonic_build::compile_protos("proto/user.proto").unwrap();
}
