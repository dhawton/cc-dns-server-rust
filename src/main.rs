#[allow(unused_imports)]
use dns_server::{
    DnsClass, DnsMessage, DnsMessageHeader, DnsName, DnsOpCode, DnsQuestion,
    DnsRecord, DnsResponseCode, DnsType
};
use std::env;
#[allow(unused_imports)]
use std::io::{Read, Write};
use std::net::Ipv4Addr;
#[allow(unused_imports)]
use std::net::UdpSocket;
use fixed_buffer::FixedBuf;

fn read_dns_name(data: &[u8], offset: &mut usize) -> Result<String, String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0usize;
    let mut pos = *offset;

    for _ in 0..128 {
        if pos >= data.len() {
            return Err("unexpected end of data reading name".into());
        }
        let len_byte = data[pos];

        if len_byte == 0 {
            if !jumped {
                *offset = pos + 1;
            }
            return Ok(labels.join("."));
        }

        // Compression pointer
        if len_byte >= 0xC0 {
            if pos + 1 >= data.len() {
                return Err("truncated compression pointer".into());
            }
            let pointer = ((len_byte as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if !jumped {
                jump_offset = pos + 2;
            }
            jumped = true;
            pos = pointer;
            continue;
        }

        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > data.len() {
            return Err("label extends past end of data".into());
        }
        let label = std::str::from_utf8(&data[pos..pos + label_len])
            .map_err(|e| format!("invalid UTF-8 in label: {e}"))?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if jumped {
        *offset = jump_offset;
    }
    Err("too many labels (possible loop)".into())
}

fn parse_dns_message(data: &[u8]) -> Result<DnsMessage, String> {
    if data.len() < 12 {
        return Err("packet too short for DNS header".into());
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags1 = data[2];
    let flags2 = data[3];

    let is_response = (flags1 & 0x80) != 0;
    let op_code = DnsOpCode::new((flags1 >> 3) & 0x0F);
    let authoritative_answer = (flags1 & 0x04) != 0;
    let truncated = (flags1 & 0x02) != 0;
    let recursion_desired = (flags1 & 0x01) != 0;
    let recursion_available = (flags2 & 0x80) != 0;
    let response_code = DnsResponseCode::new(flags2 & 0x0F);

    let question_count = u16::from_be_bytes([data[4], data[5]]);
    let answer_count = u16::from_be_bytes([data[6], data[7]]);
    let name_server_count = u16::from_be_bytes([data[8], data[9]]);
    let additional_count = u16::from_be_bytes([data[10], data[11]]);

    let mut offset = 12;
    let mut questions = Vec::new();

    for _ in 0..question_count {
        let name_str = read_dns_name(data, &mut offset)?;
        if offset + 4 > data.len() {
            return Err("truncated question record".into());
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        let name = DnsName::new(&name_str).map_err(|e| format!("invalid DNS name: {e}"))?;
        questions.push(DnsQuestion {
            name,
            typ: DnsType::new(qtype),
            class: DnsClass::new(qclass),
        });
    }

    Ok(DnsMessage {
        header: DnsMessageHeader {
            id,
            is_response,
            op_code,
            authoritative_answer,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            question_count,
            answer_count,
            name_server_count,
            additional_count,
        },
        questions,
        answers: vec![],
        name_servers: vec![],
        additional: vec![],
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("Args: {:?}", args);

    let resolver: Option<String> = args.windows(2)
        .find(|pair| pair[0] == "--resolver")
        .map(|pair| pair[1].clone());

    if let Some(ref addr) = resolver {
        println!("Using resolver: {}", addr);
    }

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let inc_message = match parse_dns_message(&buf[..size]) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to parse DNS message: {}", e);
                        eprintln!("Raw bytes ({} bytes): {:?}", size, &buf[..size]);
                        eprintln!("As string: {:?}", String::from_utf8_lossy(&buf[..size]));
                        continue;
                    }
                };
                
                let mut answers = vec![];

                for question in &inc_message.questions {
                    if let Some(ref resolver_addr) = resolver {
                        // Build a single-question query using rustdns
                        let mut query = rustdns::Message::default();
                        query.add_question(
                            question.name.inner(),
                            rustdns::types::Type::A,
                            rustdns::types::Class::Internet,
                        );

                        match query.to_vec() {
                            Ok(query_bytes) => {
                                let fwd_socket = UdpSocket::bind("0.0.0.0:0")
                                    .expect("failed to bind forwarding socket");
                                fwd_socket
                                    .set_read_timeout(Some(std::time::Duration::new(5, 0)))
                                    .expect("failed to set read timeout");
                                fwd_socket
                                    .send_to(&query_bytes, resolver_addr)
                                    .expect("failed to send to resolver");

                                let mut resp_buf = [0u8; 4096];
                                match fwd_socket.recv(&mut resp_buf) {
                                    Ok(len) => {
                                        match rustdns::Message::from_slice(&resp_buf[..len]) {
                                            Ok(resp) => {
                                                for record in &resp.answers {
                                                    if let rustdns::Resource::A(ip) = &record.resource {
                                                        answers.push(DnsRecord::A(
                                                            question.name.clone(),
                                                            *ip,
                                                        ));
                                                    }
                                                }
                                            }
                                            Err(e) => eprintln!("Failed to parse resolver response: {}", e),
                                        }
                                    }
                                    Err(e) => eprintln!("Failed to receive from resolver: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Failed to encode query: {}", e),
                        }
                    } else {
                        // No resolver, return hardcoded 127.0.0.1
                        answers.push(DnsRecord::A(
                            question.name.clone(),
                            Ipv4Addr::new(127, 0, 0, 1),
                        ));
                    }
                }

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
                        question_count: inc_message.questions.len() as u16,
                        answer_count: answers.len() as u16,
                        name_server_count: 0,
                        additional_count: 0,
                    },
                    questions: inc_message.questions.clone(),
                    answers: answers,
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
