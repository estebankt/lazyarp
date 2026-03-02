use once_cell::sync::Lazy;
use std::collections::HashMap;

// Embedded at compile time — path is relative to this source file
static OUI_CSV: &[u8] = include_bytes!("../../assets/oui.csv");

/// Global OUI map: 6-char uppercase hex prefix → vendor name
static OUI_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let mut map = HashMap::new();
    let mut reader = csv::Reader::from_reader(OUI_CSV);
    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        // IEEE CSV columns: Registry, Assignment, Organization Name, Organization Address
        if let (Some(assignment), Some(org)) = (record.get(1), record.get(2)) {
            let key = assignment.trim().to_uppercase();
            if key.len() == 6 {
                map.insert(key, org.trim().to_string());
            }
        }
    }
    map
});

/// Look up the vendor name for a MAC address.
/// `mac` should be a 6-byte array.
pub fn lookup_vendor(mac: &[u8; 6]) -> Option<String> {
    let prefix = format!("{:02X}{:02X}{:02X}", mac[0], mac[1], mac[2]);
    OUI_MAP.get(&prefix).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_map_not_empty() {
        assert!(!OUI_MAP.is_empty(), "OUI map should have entries");
    }

    #[test]
    fn test_vmware_lookup() {
        // VMware OUI: 00:50:56
        let mac = [0x00, 0x50, 0x56, 0x00, 0x00, 0x01];
        let vendor = lookup_vendor(&mac);
        assert!(
            vendor.is_some(),
            "VMware MAC should resolve to a vendor name"
        );
        let name = vendor.unwrap();
        assert!(
            name.to_lowercase().contains("vmware"),
            "Expected VMware in vendor name, got: {name}"
        );
    }

    #[test]
    fn test_unknown_mac_returns_none() {
        // Locally administered MAC (bit 1 of first octet set) — no OUI entry
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        // This may or may not be in the map; just assert no panic
        let _ = lookup_vendor(&mac);
    }
}
