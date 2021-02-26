pub mod zwift_messages;

use std::path::Path;
use pcap::{Device,Capture,Active,Offline,Activated};
use etherparse::{SlicedPacket,TransportSlice};
use protobuf::Message;
use serde::{Serialize,Deserialize};

use crate::zwift_messages::{ServerToClient, ClientToServer};


#[derive(Serialize, Deserialize, Debug)]
pub struct Player {
    pub id: i32,
    pub world_time: i64, // ms
    pub group_id: i32,

    // in game position coordinates, cm?
    pub x: f32,
    pub y: f32,

    pub heading: i64,
    pub lean: i32,

    pub road_position: i32, // ???
    pub distance: i32, // m
    pub time: i32, // sec

    pub laps: i32,
    pub speed: i32, // mm per hour
    pub climbing: i32, // m

    pub cadence: i32, // rpm
    pub heartrate: i32, // bpm
    pub power: i32, // watts

    // 15 - None, 0 - feather, 1 - draft, 5 - aero
    pub power_up: i32
}

impl Player {
    pub fn from(player_state: &zwift_messages::PlayerState) -> Self {
        Player {
            id: player_state.get_id(),
            world_time: player_state.get_worldTime(),
            group_id: player_state.get_groupId(),

            x: player_state.get_x(),
            y: player_state.get_y(),

            heading: player_state.get_heading(),
            lean: player_state.get_lean(),

            road_position: player_state.get_roadPosition(),
            distance: player_state.get_distance(),
            time: player_state.get_time(),

            laps: player_state.get_laps(),
            speed: player_state.get_speed(), // sometimes it has weird values for, near 1000 kmh
            climbing: player_state.get_climbing(),

            // it too, over 150+ rpm
            cadence: player_state.get_cadenceUHz() / 1_000 * 6 / 100,

            heartrate: player_state.get_heartrate(),
            power: player_state.get_power(),

            power_up: player_state.get_f20() & 0xf
        }
    }
}


pub enum ZwiftMessage<'a> {
    FromServer(&'a[u8]),
    ToServer(&'a[u8])
}

impl<'a> ZwiftMessage<'a> {
    pub fn get_players(&self) -> Option<Vec<Player>> {
        match self {
            ZwiftMessage::FromServer(payload) => {
                if let Ok(message) = ServerToClient::parse_from_bytes(payload) {
                    return Some(message.player_states.iter()
                        .map(|data| { Player::from(data) })
                        .collect());
                }
            },
            ZwiftMessage::ToServer(payload) => {
                // looks like protobuf message starts after X bytes with 0x8 as first byte
                // first byte seems to be used as offset index
                let offset = (payload[0] - 1) as usize;
                let limit = (payload.len() - 4) as usize;
                if let Ok(message) = ClientToServer::parse_from_bytes(&payload[offset..limit]) {
                    return Some(vec![Player::from(message.get_state())]);
                }
            }
        }
        None
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
        let _ = capture.filter("udp port 3022").unwrap();
        ZwiftCapture { capture }
    }
}

impl ZwiftCapture<Capture<Offline>> {
    pub fn from_file(path: &Path) -> Self {
        let mut capture = Capture::from_file(path).unwrap();
        let _ = capture.filter("udp port 3022").unwrap();
        ZwiftCapture { capture }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
