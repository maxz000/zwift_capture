pub mod zwift_messages;

use std::path::Path;
use pcap::{Device,Capture,Active,Offline,Activated};
use etherparse::{SlicedPacket,TransportSlice};
use protobuf::Message;
use serde::{Serialize,Deserialize};

use crate::zwift_messages::{ServerToClient, ClientToServer};


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Player {
    pub id: i32,
    pub world_time: i64, // millis
    pub group_id: i32,

    // in game position coordinates, m
    pub x: f64,
    pub y: f64,

    pub heading: i64,
    pub lean: i32,

    pub road_position: i32, // ???

    pub speed: f64, // m per sec

    pub distance: i32, // m
    pub time: i32, // sec

    pub laps: i32,
    pub climbing: i32, // m

    pub cadence: i32, // rpm
    pub heartrate: i32, // bpm
    pub power: i32, // watts

    // 15 - None, 0 - feather, 1 - draft, 5 - aero
    pub power_up: i32,
    pub watching_rider_id: i32
}

impl Player {
    pub fn from(player_state: &zwift_messages::PlayerState) -> Self {
        Player {
            id: player_state.get_id(),
            world_time: player_state.get_worldTime(),
            group_id: player_state.get_groupId(),

            // in game position coordinates, cm to m?
            x: player_state.get_x() as f64 / 100.,
            y: player_state.get_y() as f64 / 100.,

            heading: player_state.get_heading(),
            lean: player_state.get_lean(),

            road_position: player_state.get_roadPosition(),
            distance: player_state.get_distance(),
            time: player_state.get_time(),

            laps: player_state.get_laps(),
            // orginal mm per hour?
            speed: player_state.get_speed() as f64 / 1000. / 60. / 60. , // sometimes it has weird values for, near 1000 kmh
            climbing: player_state.get_climbing(),

            // it too, over 150+ rpm
            cadence: player_state.get_cadenceUHz() / 1_000 * 6 / 100,

            heartrate: player_state.get_heartrate(),
            power: player_state.get_power(),

            power_up: player_state.get_f20() & 0xf,
            watching_rider_id: player_state.get_watchingRiderId()
        }
    }
}


pub enum ZwiftMessage<'a> {
    FromServer(&'a[u8]),
    ToServer(&'a[u8])
}

impl<'a> ZwiftMessage<'a> {
    pub fn get_players(&self) -> Option<Vec<Player>> {
        return match self {
            ZwiftMessage::FromServer(payload) => {
                if let Ok(message) = ServerToClient::parse_from_bytes(payload) {
                    Some(message.player_states.iter()
                        .map(|data| { Player::from(data) })
                        .collect())
                } else {
                    Some(vec![])
                }
            },
            ZwiftMessage::ToServer(payload) => {
                // looks like protobuf message starts after X bytes with 0x8 as first byte
                // first byte seems to be used as offset index
                let mut offset = (payload[0] - 1) as usize;
                let limit = (payload.len() - 4) as usize;
                if offset >= limit {
                    for (ix, &byte) in payload.iter().enumerate() {
                        if byte == 0x8 as u8 {
                            offset = ix;
                            break
                        } else if ix == limit {
                            offset = 0;
                            break
                        }
                    }
                }
                if let Ok(message) = ClientToServer::parse_from_bytes(&payload[offset..limit]) {
                    Some(vec![Player::from(message.get_state())])
                } else {
                    Some(vec![])
                }
            }
        }
    }
}


pub struct ZwiftCapture<T>
{
    capture: T
}

impl<T: Activated> ZwiftCapture<Capture<T>> {
    pub fn next_payload(&mut self) -> Option<ZwiftMessage> {
        if let Ok(packet) = self.capture.next() {
            if let Ok(parsed) = SlicedPacket::from_ethernet(packet.data) {

                match parsed.transport {
                    Some(TransportSlice::Udp(u)) => {
                        let source_port = u.source_port();
                        return if source_port == 3022 {
                            Some(ZwiftMessage::FromServer(parsed.payload))
                        } else {
                            Some(ZwiftMessage::ToServer(parsed.payload))
                        }
                    },
                    _ => {}
                }
            }
        }
        None
    }
}

impl<T: Activated> Iterator for ZwiftCapture<Capture<T>> {
    type Item = Vec<Player>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(zwift_message) = self.next_payload() {
            if let Some(players) = zwift_message.get_players() {
                return Some(players);
            }
        }
        None
    }
}

impl ZwiftCapture<Capture<Active>> {
    pub fn new() -> Self {
        let main_device = Device::lookup().unwrap();
        let mut capture = main_device.open().unwrap();
        let _ = capture.filter("udp port 3022", true).unwrap();
        ZwiftCapture { capture }
    }

    pub fn from_device(device: Device) -> Self {
        let mut capture = device.open().unwrap();
        let _ = capture.filter("udp port 3022", true).unwrap();
        ZwiftCapture { capture }
    }
}

impl ZwiftCapture<Capture<Offline>> {
    pub fn from_file(path: &Path) -> Self {
        let mut capture = Capture::from_file(path).unwrap();
        let _ = capture.filter("udp port 3022", false).unwrap();
        ZwiftCapture { capture }
    }
}


#[cfg(test)]
mod tests {

    use hex_literal::hex;
    use crate::ZwiftMessage;

    #[test]
    fn it_works_parse_from_server() {
        let packet_payload = hex!("08011086d30618d5a3fbcce80520ca154273089dc630109da2fbcce805184220af993a280030d0d0ea0a4096adfd0448e1e13250005800602268b2c9a40170c3a13d780080010f9801958018a0018f808010a80100b80100c001a801cd01ab4a8247d501066f1c46dd01376f34c7e0019dc630e80100f801009502016ccb45980206b00201428b0108c8c1de0110caa2fbcce805188f1020ee923a280030f0f6df0440ec96c60448abeeab01500058a501600068adece1ffffffffffff017090dd3c78018001bd06980190809810a0018f808008a80180a201b001e4cdc8cce805b80100c001b08c01cd0190568147d501be411d46dd01615a39c7e001c8c1de01e80100f801019502c2074a48980206b00200427808fdcdae0110e3a2fbcce805189c06208f8e3a28003098a6a80940c68ad00448fef131500358626088016896a6df0270deee3c780480017f9801918018a0018f808010a801800cb80100c001bc1fcd01e00a8047d501ecf51d46dd012b173ac7e001fdcdae01e80100f801009502774b9a47980206b0020088017f900101980101");
        let message = ZwiftMessage::FromServer(&packet_payload);
        let players = message.get_players().unwrap();
    }

    #[test]
    fn it_works_parse_to_server() {
        let packet_payload = hex!("0686a9010008011086d30618e1a6fbcce80520ab023a6e0886d30610e1a6fbcce8051800208fac3a2800300040f4fa860548005000584f600068cbd5aa0170c0843d7800800100980195809808a0018f808008a80100b80100c00100cd01ae378847d50119191a46dd01a0d52ec7e00186d306e80100f80100950200000000980206b002001f403176");
        let message = ZwiftMessage::ToServer(&packet_payload);
        let players = message.get_players().unwrap();
        assert_eq!(players.len(), 1);
    }

    #[test]
    fn clone_player() {
        let packet_payload = hex!("0686a9010008011086d30618e1a6fbcce80520ab023a6e0886d30610e1a6fbcce8051800208fac3a2800300040f4fa860548005000584f600068cbd5aa0170c0843d7800800100980195809808a0018f808008a80100b80100c00100cd01ae378847d50119191a46dd01a0d52ec7e00186d306e80100f80100950200000000980206b002001f403176");
        let message = ZwiftMessage::ToServer(&packet_payload);
        let player = message.get_players().unwrap().pop().unwrap();
        let player_copy = player.clone();
    }
}
