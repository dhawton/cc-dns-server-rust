#[allow(unused_imports)]
use std::net::UdpSocket;

struct DNSHeader {
    id: u16,
    query_response_indicator: bool,
    opcode: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    reserved: u8,
    response_code: u8,

    question_count: u16,
    answer_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

impl DNSHeader {
    fn pack(&self) -> u16 {
        let mut flags: u16 = 0;

        flags |= (self.query_response_indicator as u16) << 15;
        flags |= ((self.opcode & 0x0F) as u16) << 11;
        flags |= (self.authoritative_answer as u16) << 10;
        flags |= (self.truncation as u16) << 9;
        flags |= (self.recursion_desired as u16) << 8;
        flags |= (self.recursion_available as u16) << 7;
        flags |= ((self.reserved & 0x07) as u16) << 4;
        flags |= (self.response_code & 0x0F) as u16;

        flags
    }

    fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];

        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());

        let flags = self.pack();
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.question_count.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.answer_count.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.authority_record_count.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.additional_record_count.to_be_bytes());

        bytes
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                // Hardcoded response for now
                let request_id = u16::from_be_bytes([buf[0], buf[1]]);
                let header = DNSHeader {
                    id: request_id,
                    query_response_indicator: true,
                    opcode: 0,
                    authoritative_answer: false,
                    truncation: false,
                    recursion_desired: false,
                    recursion_available: false,
                    reserved: 0,
                    response_code: 0,
                    question_count: 0,
                    answer_count: 0,
                    authority_record_count: 0,
                    additional_record_count: 0,
                };
                let response = header.to_bytes();

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
