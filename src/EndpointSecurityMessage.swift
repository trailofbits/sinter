import EndpointSecurity

struct EndpointSecurityMessage {
  var unsafe_msg_ptr: UnsafeMutablePointer<es_message_t>;
  var binary_path: String;
  var signature_status: CodeSignatureStatus?;
}

