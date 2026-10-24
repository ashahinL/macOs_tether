//! One RNDIS init, MAC query, and packet-filter set. Exits when that is done.

use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use tether::rndis::{
    self, parse_init_cmplt, parse_query_cmplt, parse_set_cmplt, Message, OUR_MAX_TRANSFER_SIZE,
};
use tether::usb::{self, ListedDevice, UsbError};

const OID_802_3_PERMANENT_ADDRESS: u32 = 0x0101_0101;
const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
const PACKET_FILTER: u32 = 0x0000_000F;

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("{line}");
            ExitCode::from(0)
        }
        Err(RunError::NoRndis(devices)) => {
            println!("no RNDIS interface");
            if devices.is_empty() {
                println!("no USB devices read");
            }
            for device in devices {
                print_device(&device);
            }
            ExitCode::from(2)
        }
        Err(RunError::Access(msg)) => {
            println!("{msg}");
            ExitCode::from(3)
        }
        Err(RunError::Failed(msg)) => {
            println!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, RunError> {
    let scan = usb::list_devices()?;
    let Some(found) = scan
        .devices
        .iter()
        .find(|device| device.rndis.is_some())
        .cloned()
    else {
        let saw_interface = scan
            .devices
            .iter()
            .any(|device| !device.interfaces.is_empty());
        let saw_access =
            scan.hidden_by_access || scan.devices.iter().any(|device| device.access_denied);
        if !saw_interface && saw_access {
            return Err(RunError::Access(
                "Access denied (insufficient permissions)".into(),
            ));
        }
        return Err(RunError::NoRndis(scan.devices));
    };
    let rndis = found.rndis.as_ref().expect("rndis match");
    let device = usb::claim(found.bus, found.address, found.vid, found.pid, rndis)?;

    device.send_command(&rndis::build_init(1))?;
    thread::sleep(Duration::from_millis(100));
    let init = match parse_init_cmplt(&device.read_response()?)? {
        Message::InitComplete {
            max_packets_per_transfer,
            max_transfer_size,
            ..
        } => (max_packets_per_transfer, max_transfer_size),
        other => {
            return Err(RunError::Failed(format!("INIT_CMPLT: {other:?}")));
        }
    };

    device.send_command(&rndis::build_query(2, OID_802_3_PERMANENT_ADDRESS, &[]))?;
    thread::sleep(Duration::from_millis(50));
    let mac = match parse_query_cmplt(&device.read_response()?)? {
        Message::QueryComplete { data, .. } => data,
        other => {
            return Err(RunError::Failed(format!("QUERY_CMPLT: {other:?}")));
        }
    };
    if mac.len() != 6 {
        return Err(RunError::Failed(format!("MAC is {} bytes", mac.len())));
    }

    device.send_command(&rndis::build_set(
        3,
        OID_GEN_CURRENT_PACKET_FILTER,
        &PACKET_FILTER.to_le_bytes(),
    ))?;
    thread::sleep(Duration::from_millis(50));
    match parse_set_cmplt(&device.read_response()?)? {
        Message::SetComplete { .. } => {}
        other => {
            return Err(RunError::Failed(format!("SET_CMPLT: {other:?}")));
        }
    }

    let (max_packets_per_transfer, phone_max_transfer_size) = init;
    Ok(format!(
        "vid={:04x} pid={:04x} mac={} our_max_transfer_size={} phone_max_transfer_size={} max_packets_per_transfer={}",
        device.vid,
        device.pid,
        format_mac(&mac),
        OUR_MAX_TRANSFER_SIZE,
        phone_max_transfer_size,
        max_packets_per_transfer,
    ))
}

fn print_device(device: &ListedDevice) {
    println!("vid={:04x} pid={:04x}", device.vid, device.pid);
    if device.access_denied {
        println!("  access denied");
        return;
    }
    if device.interfaces.is_empty() {
        println!("  no interfaces read");
        return;
    }
    for iface in &device.interfaces {
        println!(
            "  interface {} class={:02x} subclass={:02x} protocol={:02x}",
            iface.number, iface.class_code, iface.subclass, iface.protocol
        );
    }
}

fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

enum RunError {
    NoRndis(Vec<ListedDevice>),
    Access(String),
    Failed(String),
}

impl From<UsbError> for RunError {
    fn from(err: UsbError) -> Self {
        match err {
            UsbError::Access(msg) => RunError::Access(msg),
            UsbError::Other(msg) => RunError::Failed(msg),
        }
    }
}

impl From<rndis::RndisError> for RunError {
    fn from(err: rndis::RndisError) -> Self {
        RunError::Failed(format!("{err:?}"))
    }
}
