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
