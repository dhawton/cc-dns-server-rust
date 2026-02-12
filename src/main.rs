use rustdns::{Class, Message, QR, Type};
#[allow(unused_imports)]
use std::net::UdpSocket;

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
                let mut message = Message::default();
                message.id = request_id;
                message.qr = QR::Response;

                message.add_question("codecrafters.io", Type::A, Class::Internet);
                
                let response = message.to_vec().unwrap();

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
