mod client;
mod crypto;
mod server;

use clap::{ App, load_yaml };
use std::error::Error;
use std::fs::File;
use std::io::Read;

const RECV_BUFFER_BSIZE:   usize = 1024;
const SHARED_SECRET_BSIZE: usize = 32;

fn greet() {
    println!("===================================================");
    println!("---------------- Welcome to 🦀 VPN ----------------");
    println!("===================================================");
}

fn main() -> Result<(), Box<dyn Error>>{

    let config = load_yaml!("cli.yml");
    let settings = App::from_yaml(config).get_matches();

    greet();

    if settings.is_present("client") {
        let settings = settings.subcommand_matches("client").unwrap();
        let host = settings.value_of("host").unwrap();
        let port = settings.value_of("port").unwrap();

        let client = client::Client::new(host, port);

        let log = client.run(vec![String::from("plaintext message"),
                                  String::from("plaintext message again")])?;
        print_log(log);

    } else if settings.is_present("server") {
        let settings = settings.subcommand_matches("server").unwrap();
        let port = settings.value_of("port").unwrap();

        let server = server::Server::new(port);

        server.run()?;
    }


    Ok(())
}

pub fn print_log(log: Vec<String>) {
    for msg in log {
        println!("{}", msg);
    }
}
