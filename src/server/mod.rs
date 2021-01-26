use crate::RECV_BUFFER_BSIZE;
use crate::print_log;
use crate::crypto;

use base64;
use std::error::Error;
use std::io::{Read};
use std::net::{TcpListener, TcpStream};

pub struct Server {
    port: String,
}

impl Server {
    pub fn new(port: &str) -> Server {
        println!("Server Mode: Awaiting connection on port {}", port);

        let port = String::from(port);
        Server { port }
    }

    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))?;

        for stream in listener.incoming() {
            let stream = stream?;

            let log = handle_cxn(stream)?;
            print_log(log);
        }

        Ok(())
    }

}

fn handle_cxn(unauth_stream: TcpStream) -> Result<Vec<String>, Box<dyn Error>> {
    let mut log = Vec::new();
    let (mut auth_stream, session) = crypto::auth_cxn(unauth_stream)?;
    log.push(
        format!("Proceeding with key: {}",
                base64::encode(&session.key)));

    let mut buffer = [0; RECV_BUFFER_BSIZE];
    let len = auth_stream.read(&mut buffer)?;

    let cyphertext = base64::encode(&buffer[..len]);
    let plaintext = crypto::decrypt(&buffer[..len], &session)?;
    log.push(format!("decrypted {} (base64) as {}",
                     cyphertext,
                     plaintext));

    Ok(log)
}
