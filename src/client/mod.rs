use crate::crypto;

use base64;
use std::error::Error;
use std::io::{Write};
use std::net::TcpStream;
use std::vec::Vec;

pub struct Client {
    addr: String,
    session: Option<crypto::Session>,
}

impl Client {
    pub fn new(host: &str, port: &str) -> Client {
        println!("Client Mode: Using address:port {}:{}", host, port);

        let addr = String::from(format!("{}:{}", host, port));
        Client { addr, session : None, }
    }

    pub fn run(&self, msgs: Vec<String>) -> Result<Vec<String>, Box<dyn Error>> {
        let mut log = Vec::new();
        let stream = TcpStream::connect(&self.addr.as_str())?;

        let (mut auth_stream, session) = crypto::auth_cxn(stream)?;
        log.push(format!("Proceeding with key: {}",
                         base64::encode(&session.key)));

        for msg in msgs {
            let cyphertext = crypto::encrypt(&msg.as_bytes(), &session)?;
            auth_stream.write(&cyphertext)?;

            log.push(format!("sent {} as {} (base64)",
                             msg,
                             base64::encode(cyphertext)));
        }

        Ok(log)
    }
}
