use std::net::UdpSocket;
use std::fs::File;
use std::io::prelude::*;
use std::time::SystemTime;
use dns_rust::message::rdata::Rdata;
use dns_rust::message::DnsMessage;
use dns_rust;
use base64;
use base64::{Engine as _};
use dns_rust::tsig::process_tsig;

fn recv_dig() {
    let key = b"7niAlAtSA70XRNgvlAB5m80ywDA=";
    let key_bytes = base64::prelude::BASE64_STANDARD.decode(key).unwrap();
    let mut lista_alg = vec![];
    lista_alg.push((String::from("hmac-sha1"),true));

    let socket_udp = UdpSocket::bind("127.0.0.1:8887").expect("Failed to bind to address");
    let socket_udp2 = UdpSocket::bind("192.168.100.2:8890").expect("Failed to bind to address");
    let mut buf = [0;1000];
    let (s, addr_in) = socket_udp.recv_from(&mut buf).unwrap();
    //println!("Llego un mensaje de largo {s}");
    let bytes = &buf[0..s].to_vec();
    let dnsmsg = DnsMessage::from_bytes(bytes).expect("Parseo mal!");

    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let mac = vec![];
    let (a, b)= process_tsig(&dnsmsg,  &key_bytes, "weird.nictest".to_string(), time, lista_alg.clone(), mac);

    println!("Verificando la query del cliente!");
    println!("bool: {:?} tsig_err: {:#?}", a, b);
    println!("-----------------------------------------------------");

    // println!("{:#?}", dnsmsg.get_header());
    let rrs = dnsmsg.get_additional().pop().unwrap();
    let tsig = match rrs.get_rdata() {
        Rdata::TSIG(xd) => {
            xd
        },
        _ => panic!("xd")
    };


    let mac = tsig.get_mac();
    let test_bytes = dnsmsg.to_bytes();

    socket_udp2.send_to(&test_bytes, "192.168.100.3:53").unwrap();

    let mut buf2 = [0; 2000];
    let (s2, _) = socket_udp2.recv_from(& mut buf2).unwrap();
    let bytes2 = &buf2[0..s2].to_vec();
    let dnsmsg2 = DnsMessage::from_bytes(&bytes2[0..s2]).expect("Parseo mal!");

    let mut response_dns_tsig_file = File::create("response_tsig_cliente.dns").unwrap();
    response_dns_tsig_file.write_all(bytes2).expect("Error al escribir el archivo");

    let parsed_bytes = dnsmsg2.to_bytes();

    socket_udp.send_to(&parsed_bytes, addr_in).unwrap();
    //process_tsig(&dnsmsg2, key, key_name, time, available_algorithm, mac_to_process)


    //panic!();
    //let bytes = general_purpose::STANDARD.decode(key).unwrap();
    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let (a, b)= process_tsig(&dnsmsg2,  &key_bytes, "weird.nictest".to_string(), time, lista_alg, mac);
    println!("Verificando la respuesta del servidor");
    println!("bool: {:?} tsig_err: {:#?}", a, b);
    }

fn main() {
    recv_dig()
}