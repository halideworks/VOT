// Generated from spec/registries.yaml by tools/generate_registries.py.
// Do not edit.

frame_registry! {
    HELLO = 0x01, limit: 4 * 1024, auth: exempt, extension: none;
    SETTINGS = 0x03, limit: 16 * 1024, auth: exempt, extension: none;
    SETTINGS_ACK = 0x05, limit: 0, auth: exempt, extension: none;
    AUTH_CONTEXT = 0x07, limit: 64 * 1024, auth: exempt, extension: none;
    SESSION_OPEN = 0x09, limit: 64 * 1024, auth: exempt, extension: none;
    SESSION_ACCEPT = 0x0b, limit: 64 * 1024, auth: exempt, extension: none;
    SESSION_REJECT = 0x0d, limit: 64 * 1024, auth: exempt, extension: none;
    PACKAGE_DESCRIPTOR = 0x21, limit: 1024 * 1024, auth: required, extension: none;
    MANIFEST_REQUEST = 0x23, limit: 64 * 1024, auth: required, extension: none;
    MANIFEST_PAGE = 0x25, limit: 1024 * 1024, auth: required, extension: none;
    PROGRESSIVE_PAGE = 0x27, limit: 1024 * 1024, auth: required, extension: none;
    SEAL = 0x29, limit: 256 * 1024, auth: required, extension: none;
    HAVE = 0x2b, limit: 4 * 1024 * 1024, auth: required, extension: none;
    RANGE_REQUEST = 0x2d, limit: 1024 * 1024, auth: required, extension: none;
    PROOF_BUNDLE = 0x2f, limit: HARD_MAX_FRAME_PAYLOAD, auth: required, extension: none;
    DATA_RECORD = 0x31, limit: 256 * 1024, auth: required, extension: none;
    RANGE_CANCEL = 0x33, limit: 64 * 1024, auth: required, extension: none;
    CAPACITY = 0x40, limit: 4 * 1024, auth: required, extension: none;
    TRANSIT_VERIFIED = 0x43, limit: 64 * 1024, auth: required, extension: none;
    CHUNK_DURABLE = 0x45, limit: 64 * 1024, auth: required, extension: none;
    CHUNK_AT_REST_VERIFIED = 0x47, limit: 64 * 1024, auth: required, extension: none;
    PUBLISH_RECEIPT = 0x49, limit: 64 * 1024, auth: required, extension: none;
    DATAGRAM_CREDIT = 0x60, limit: 4 * 1024, auth: required, extension: DATAGRAM_FEC;
    CODING_EPOCH_OPEN = 0x62, limit: 64 * 1024, auth: required, extension: DATAGRAM_FEC;
    GEN_STATE = 0x64, limit: 64 * 1024, auth: required, extension: DATAGRAM_FEC;
    GEN_DONE = 0x66, limit: 64 * 1024, auth: required, extension: DATAGRAM_FEC;
    CODING_EPOCH_CLOSE = 0x68, limit: 64 * 1024, auth: required, extension: DATAGRAM_FEC;
    PING = 0x80, limit: 0, auth: exempt, extension: none;
    GOAWAY = 0x83, limit: 4 * 1024, auth: required, extension: none;
    ERROR = 0x85, limit: 64 * 1024, auth: exempt, extension: none;
    SOURCE_SCORE_HINT = 0x86, limit: 64 * 1024, auth: required, extension: none;
    JOB_PRIORITY_UPDATE = 0x89, limit: 64 * 1024, auth: required, extension: none;
}
