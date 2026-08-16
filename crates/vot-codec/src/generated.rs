// Generated from spec/registries.yaml by tools/generate_registries.py.
// Do not edit.

pub mod setting_id {
    pub const MAX_CONTROL_FRAME_PAYLOAD: u64 = 0x01;
    pub const MAX_DATA_RECORD_PAYLOAD: u64 = 0x03;
    pub const MAX_MANIFEST_PAGE_PAYLOAD: u64 = 0x05;
    pub const RELIABLE_LANE_LIMIT: u64 = 0x07;
    pub const IDLE_TIMEOUT_MS: u64 = 0x09;

    /// Identifiers the registry retired, kept so nothing reassigns them.
    pub const RETIRED: [u64; 3] = [0x0b, 0x20, 0x22];
}

/// The registered default of each setting.
pub mod setting_default {
    pub const MAX_CONTROL_FRAME_PAYLOAD: u64 = 1_048_576;
    pub const MAX_DATA_RECORD_PAYLOAD: u64 = 262_144;
    pub const MAX_MANIFEST_PAGE_PAYLOAD: u64 = 1_048_576;
    pub const RELIABLE_LANE_LIMIT: u64 = 16;
    pub const IDLE_TIMEOUT_MS: u64 = 90_000;
}

/// The inclusive value range of each setting.
pub mod setting_bounds {
    pub const MAX_CONTROL_FRAME_PAYLOAD: (u64, u64) = (1_024, 16_777_216);
    pub const MAX_DATA_RECORD_PAYLOAD: (u64, u64) = (65_536, 262_144);
    pub const MAX_MANIFEST_PAGE_PAYLOAD: (u64, u64) = (65_536, 1_048_576);
    pub const RELIABLE_LANE_LIMIT: (u64, u64) = (1, 256);
    pub const IDLE_TIMEOUT_MS: (u64, u64) = (1_000, 600_000);
}

/// What a capability authorizes.
pub mod operation {
    pub const PUBLISH: u64 = 0x0001;
    pub const READ_MANIFEST: u64 = 0x0002;
    pub const READ_RANGES: u64 = 0x0003;
}

/// What a capability may cap.
pub mod resource_limit {
    pub const CONCURRENT_LANES: u64 = 0x0001;
    pub const WIRE_BYTES: u64 = 0x0002;
    pub const STORAGE_BYTES: u64 = 0x0003;
}

/// Extension identifiers.
pub mod extension_id {
    pub const CORE_RELIABLE: u64 = 0x00;
    pub const DATAGRAM_FEC: u64 = 0x01;
    pub const ZSTD_RECORDS: u64 = 0x02;
    pub const VCRC: u64 = 0x03;
    pub const PUBLIC_MULTI_RAIL: u64 = 0x04;
    pub const CUSTOM_CONGESTION_CONTROL: u64 = 0x05;
    pub const MULTIPATH_QUIC: u64 = 0x06;
}

pub mod error_code {
    pub const UNKNOWN_CRITICAL_FRAME: u16 = 0x0101;
    pub const MALFORMED_FRAME: u16 = 0x0102;
    pub const FRAME_TOO_LARGE: u16 = 0x0103;
    pub const UNSUPPORTED_VERSION: u16 = 0x0104;
    pub const INVALID_SETTING: u16 = 0x0105;
    pub const DUPLICATE_SETTING: u16 = 0x0106;
    pub const AUTHENTICATION_FAILED: u16 = 0x0201;
    pub const AUTHORIZATION_FAILED: u16 = 0x0202;
    pub const REPLAY_REJECTED: u16 = 0x0203;
    pub const MANIFEST_INVALID: u16 = 0x0301;
    pub const OBJECT_IDENTITY_MISMATCH: u16 = 0x0302;
    pub const PROOF_INVALID: u16 = 0x0303;
    pub const SOURCE_MUTATED: u16 = 0x0304;
    pub const STORAGE_WRITE_FAILED: u16 = 0x0401;
    pub const DURABILITY_FAILED: u16 = 0x0402;
    pub const AT_REST_VERIFICATION_FAILED: u16 = 0x0403;
    pub const PUBLICATION_FAILED: u16 = 0x0404;
    pub const STALE_INCARNATION: u16 = 0x0405;
    pub const ASSURANCE_UNSUPPORTED: u16 = 0x0406;
    pub const ADMISSION_DENIED: u16 = 0x0501;
    pub const RESOURCE_LIMIT: u16 = 0x0502;
    pub const FLOW_CONTROL_VIOLATION: u16 = 0x0503;
    pub const CARRIER_UNAVAILABLE: u16 = 0x0601;
    pub const PATH_STATE_REJECTED: u16 = 0x0602;
    pub const EXPERIMENT_NOT_NEGOTIATED: u16 = 0x0701;
    pub const RISK_BUDGET_EXHAUSTED: u16 = 0x0702;
    pub const CODING_EPOCH_CONFLICT: u16 = 0x0703;
}

/// Every registered setting, in identifier order.
pub const REGISTERED_SETTINGS: [u64; 5] = [
    setting_id::MAX_CONTROL_FRAME_PAYLOAD,
    setting_id::MAX_DATA_RECORD_PAYLOAD,
    setting_id::MAX_MANIFEST_PAGE_PAYLOAD,
    setting_id::RELIABLE_LANE_LIMIT,
    setting_id::IDLE_TIMEOUT_MS,
];

/// Every registered operation, in identifier order.
pub const REGISTERED_OPERATIONS: [u64; 3] = [
    operation::PUBLISH,
    operation::READ_MANIFEST,
    operation::READ_RANGES,
];

/// Every registered resource limit, in identifier order.
pub const REGISTERED_LIMITS: [u64; 3] = [
    resource_limit::CONCURRENT_LANES,
    resource_limit::WIRE_BYTES,
    resource_limit::STORAGE_BYTES,
];
