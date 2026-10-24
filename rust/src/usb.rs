//! Find an RNDIS phone and send CDC encapsulated commands on its comm interface.

use std::time::Duration;

use rusb::{Context, DeviceHandle, Direction, TransferType, UsbContext};

const CTRL_TIMEOUT: Duration = Duration::from_secs(5);
const CTRL_BUF: usize = 4096;

const COMM_FILTERS: [(u8, u8, u8); 4] = [
    (0xE0, 0x01, 0x03),
    (0x02, 0x02, 0x03),
    (0x02, 0xFF, 0x03),
    (0xFF, 0x01, 0x03),
];
const CDC_DATA_CLASS: u8 = 0x0A;

#[derive(Debug)]
pub enum UsbError {
    Access(String),
    Other(String),
}

impl std::fmt::Display for UsbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbError::Access(msg) | UsbError::Other(msg) => f.write_str(msg),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceClass {
    pub number: u8,
    pub class_code: u8,
    pub subclass: u8,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RndisInterfaces {
    pub comm: u8,
    pub data: u8,
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub interrupt: u8,
}

#[derive(Debug, Clone)]
pub struct ListedDevice {
    pub bus: u8,
    pub address: u8,
    pub vid: u16,
    pub pid: u16,
    pub interfaces: Vec<InterfaceClass>,
    pub rndis: Option<RndisInterfaces>,
    /// Config descriptor could not be read because libusb returned access denied.
    pub access_denied: bool,
}

pub struct DeviceScan {
    pub devices: Vec<ListedDevice>,
    /// A device descriptor itself was access-denied, so that device is missing above.
    pub hidden_by_access: bool,
}

pub struct ClaimedDevice {
    handle: DeviceHandle<Context>,
    detached: Vec<u8>,
    pub vid: u16,
    pub pid: u16,
    pub comm_iface: u8,
    pub data_iface: u8,
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub interrupt: u8,
}

impl Drop for ClaimedDevice {
    fn drop(&mut self) {
        if self.data_iface != self.comm_iface {
            let _ = self.handle.release_interface(self.data_iface);
        }
        let _ = self.handle.release_interface(self.comm_iface);
        for iface in &self.detached {
            let _ = self.handle.attach_kernel_driver(*iface);
        }
    }
}

impl ClaimedDevice {
    pub fn send_command(&self, data: &[u8]) -> Result<(), UsbError> {
        let request_type = rusb::request_type(
            Direction::Out,
            rusb::RequestType::Class,
            rusb::Recipient::Interface,
        );
        let written = self
            .handle
            .write_control(
                request_type,
                0x00,
                0,
                u16::from(self.comm_iface),
                data,
                CTRL_TIMEOUT,
            )
            .map_err(map_err)?;
        if written != data.len() {
            return Err(UsbError::Other(format!(
                "short control write {written} of {}",
                data.len()
            )));
        }
        Ok(())
    }

    pub fn read_response(&self) -> Result<Vec<u8>, UsbError> {
        let request_type = rusb::request_type(
            Direction::In,
            rusb::RequestType::Class,
            rusb::Recipient::Interface,
        );
        let mut buf = vec![0u8; CTRL_BUF];
        let read = self
            .handle
            .read_control(
                request_type,
                0x01,
                0,
                u16::from(self.comm_iface),
                &mut buf,
                CTRL_TIMEOUT,
            )
            .map_err(map_err)?;
        buf.truncate(read);
        Ok(buf)
    }
}

pub fn list_devices() -> Result<DeviceScan, UsbError> {
    let context = Context::new().map_err(map_err)?;
    let devices = context.devices().map_err(map_err)?;
    let mut listed = Vec::new();
    let mut hidden_by_access = false;
    for device in devices.iter() {
        match read_device(&device)? {
            Read::Device(seen) => listed.push(seen),
            Read::Hidden => hidden_by_access = true,
            Read::Skip => {}
        }
    }
    Ok(DeviceScan {
        devices: listed,
        hidden_by_access,
    })
}

pub fn claim(
    bus: u8,
    address: u8,
    vid: u16,
    pid: u16,
    rndis: &RndisInterfaces,
) -> Result<ClaimedDevice, UsbError> {
    let context = Context::new().map_err(map_err)?;
    let devices = context.devices().map_err(map_err)?;
    let device = devices
        .iter()
        .find(|device| device.bus_number() == bus && device.address() == address)
        .ok_or_else(|| UsbError::Other(format!("device {vid:04x}:{pid:04x} disappeared")))?;
    let handle = device.open().map_err(map_err)?;

    let mut detached = Vec::new();
    if let Err(err) = detach_if_active(&handle, rndis.comm, &mut detached) {
        reattach(&handle, &detached);
        return Err(err);
    }
    if rndis.data != rndis.comm {
        if let Err(err) = detach_if_active(&handle, rndis.data, &mut detached) {
            reattach(&handle, &detached);
            return Err(err);
        }
    }

    if let Err(err) = handle.claim_interface(rndis.comm) {
        reattach(&handle, &detached);
        return Err(map_err(err));
    }
    if rndis.data != rndis.comm {
        if let Err(err) = handle.claim_interface(rndis.data) {
            let _ = handle.release_interface(rndis.comm);
            reattach(&handle, &detached);
            return Err(map_err(err));
        }
    }

    Ok(ClaimedDevice {
        handle,
        detached,
        vid,
        pid,
        comm_iface: rndis.comm,
        data_iface: rndis.data,
        bulk_in: rndis.bulk_in,
        bulk_out: rndis.bulk_out,
        interrupt: rndis.interrupt,
    })
}

enum Read {
    Device(ListedDevice),
    Hidden,
    Skip,
}

fn read_device<T: UsbContext>(device: &rusb::Device<T>) -> Result<Read, UsbError> {
    let desc = match device.device_descriptor() {
        Ok(desc) => desc,
        Err(rusb::Error::Access) => return Ok(Read::Hidden),
        Err(_) => return Ok(Read::Skip),
    };
    let vid = desc.vendor_id();
    let pid = desc.product_id();
    let bus = device.bus_number();
    let address = device.address();

    let config = match device.active_config_descriptor() {
        Ok(config) => config,
        Err(rusb::Error::Access) => {
            return Ok(Read::Device(denied_device(bus, address, vid, pid)));
        }
        Err(_) => match device.config_descriptor(0) {
            Ok(config) => config,
            Err(rusb::Error::Access) => {
                return Ok(Read::Device(denied_device(bus, address, vid, pid)));
            }
            Err(_) => {
                return Ok(Read::Device(ListedDevice {
                    bus,
                    address,
                    vid,
                    pid,
                    interfaces: Vec::new(),
                    rndis: None,
                    access_denied: false,
                }));
            }
        },
    };

    let mut interfaces = Vec::new();
    for iface in config.interfaces() {
        for alt in iface.descriptors() {
            interfaces.push(InterfaceClass {
                number: alt.interface_number(),
                class_code: alt.class_code(),
                subclass: alt.sub_class_code(),
                protocol: alt.protocol_code(),
            });
        }
    }

    let rndis = select_rndis(&interfaces).map(|(comm, data)| {
        let mut found = RndisInterfaces {
            comm,
            data,
            bulk_in: 0,
            bulk_out: 0,
            interrupt: 0,
        };
        for iface in config.interfaces() {
            for alt in iface.descriptors() {
                let number = alt.interface_number();
                if number != comm && number != data {
                    continue;
                }
                for endpoint in alt.endpoint_descriptors() {
                    match endpoint.transfer_type() {
                        TransferType::Interrupt if number == comm && found.interrupt == 0 => {
                            found.interrupt = endpoint.address();
                        }
                        TransferType::Bulk => match endpoint.direction() {
                            Direction::In if found.bulk_in == 0 => {
                                found.bulk_in = endpoint.address();
                            }
                            Direction::Out if found.bulk_out == 0 => {
                                found.bulk_out = endpoint.address();
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
        found
    });

    Ok(Read::Device(ListedDevice {
        bus,
        address,
        vid,
        pid,
        interfaces,
        rndis,
        access_denied: false,
    }))
}

fn denied_device(bus: u8, address: u8, vid: u16, pid: u16) -> ListedDevice {
    ListedDevice {
        bus,
        address,
        vid,
        pid,
        interfaces: Vec::new(),
        rndis: None,
        access_denied: true,
    }
}

fn select_rndis(interfaces: &[InterfaceClass]) -> Option<(u8, u8)> {
    let comm = interfaces
        .iter()
        .find(|iface| COMM_FILTERS.contains(&(iface.class_code, iface.subclass, iface.protocol)))?
        .number;
    let data = interfaces
        .iter()
        .find(|iface| iface.class_code == CDC_DATA_CLASS && iface.number != comm)
        .map(|iface| iface.number)
        .or_else(|| {
            let next = comm.wrapping_add(1);
            interfaces
                .iter()
                .any(|iface| iface.number == next)
                .then_some(next)
        })?;
    Some((comm, data))
}

fn detach_if_active(
    handle: &DeviceHandle<Context>,
    iface: u8,
    detached: &mut Vec<u8>,
) -> Result<(), UsbError> {
    match handle.kernel_driver_active(iface) {
        Ok(true) => {
            handle.detach_kernel_driver(iface).map_err(map_err)?;
            detached.push(iface);
            Ok(())
        }
        Ok(false) | Err(rusb::Error::NotSupported) => Ok(()),
        Err(err) => Err(map_err(err)),
    }
}

fn reattach(handle: &DeviceHandle<Context>, detached: &[u8]) {
    for iface in detached {
        let _ = handle.attach_kernel_driver(*iface);
    }
}

fn map_err(err: rusb::Error) -> UsbError {
    let text = err.to_string();
    match err {
        rusb::Error::Access => UsbError::Access(text),
        _ if text.to_ascii_lowercase().contains("access denied") => UsbError::Access(text),
        _ => UsbError::Other(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(number: u8, class_code: u8, subclass: u8, protocol: u8) -> InterfaceClass {
        InterfaceClass {
            number,
            class_code,
            subclass,
            protocol,
        }
    }

    #[test]
    fn comm_filters_match_a_separate_data_interface() {
        for (class_code, subclass, protocol) in COMM_FILTERS {
            let interfaces = vec![
                iface(0, class_code, subclass, protocol),
                iface(1, CDC_DATA_CLASS, 0x00, 0x00),
            ];
            assert_eq!(select_rndis(&interfaces), Some((0, 1)));
        }
    }

    #[test]
    fn data_interface_listed_first_still_matches() {
        let interfaces = vec![iface(1, CDC_DATA_CLASS, 0, 0), iface(0, 0xE0, 0x01, 0x03)];
        assert_eq!(select_rndis(&interfaces), Some((0, 1)));
    }

    #[test]
    fn next_interface_is_used_when_no_cdc_data_class() {
        let interfaces = vec![iface(2, 0x02, 0x02, 0x03), iface(3, 0xFF, 0x00, 0x00)];
        assert_eq!(select_rndis(&interfaces), Some((2, 3)));
    }

    #[test]
    fn no_data_interface_is_not_rndis() {
        let interfaces = vec![iface(2, 0xFF, 0x01, 0x03)];
        assert_eq!(select_rndis(&interfaces), None);
    }
}
