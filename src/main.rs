#[allow(unused_imports)]
use dns_server::{
    DnsClass, DnsMessage, DnsMessageHeader, DnsName, DnsOpCode, DnsQuestion,
    DnsRecord, DnsResponseCode, DnsType
};
#[allow(unused_imports)]
use std::io::{Read, Write};
use std::net::Ipv4Addr;
#[allow(unused_imports)]
use std::net::UdpSocket;
use fixed_buffer::FixedBuf;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let mut read_buf: FixedBuf<512> = FixedBuf::new();
                read_buf.write(buf.as_ref()).expect("failed to read");
                eprintln!(" ---> {}", read_buf.len());
                let inc_message = DnsMessage::read(&mut read_buf).unwrap();
                eprintln!("Inc message: {:?}", inc_message);
                
                let question = DnsQuestion {
                    name: DnsName::new("codecrafters.io").unwrap(),
                    typ: DnsType::A,
                    class: DnsClass::Internet,
                };

                let answer = DnsRecord::A(
                    DnsName::new("codecrafters.io").unwrap(),
                    Ipv4Addr::new(127, 0, 0, 1),
                );

                let message = DnsMessage {
                    header: DnsMessageHeader {
                        id: inc_message.header.id,
                        is_response: true,
                        op_code: inc_message.header.op_code,
                        authoritative_answer: false,
                        truncated: false,
                        recursion_desired: inc_message.header.recursion_desired,
                        recursion_available: false,
                        response_code: DnsResponseCode::NotImplemented,
                        question_count: 1,
                        answer_count: 1,
                        name_server_count: 0,
                        additional_count: 0,
                    },
                    questions: vec![question],
                    answers: vec![answer],
                    name_servers: vec![],
                    additional: vec![],
                };
                
                let mut buf: FixedBuf<4096> = FixedBuf::new();
                message.write(&mut buf).expect("panic");

                udp_socket
                    .send_to(&buf.read_bytes(buf.len()), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
