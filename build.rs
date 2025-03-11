fn main() {
    tonic_build::compile_protos("proto/user.proto").unwrap();
    tonic_build::compile_protos("proto/auth.proto").unwrap();
    tonic_build::compile_protos("proto/kyc.proto").unwrap();
    tonic_build::compile_protos("proto/upload.proto").unwrap();
}
