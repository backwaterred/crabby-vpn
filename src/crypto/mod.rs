use crate::SHARED_SECRET_BSIZE;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand_core::OsRng;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

// create an alias for convenience
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// FIXME See below
use hex_literal::hex;

pub const KEY_BSIZE: usize   = 32;
pub const BLOCK_BSIZE: usize = 16;

pub struct Session {
    pub key: [u8; KEY_BSIZE],
    pub iv: [u8; BLOCK_BSIZE],
}

pub fn auth_cxn(mut unauth_stream: TcpStream)
                -> Result<(TcpStream, Session), Box<dyn Error>> {

    let mut buffer: [u8; SHARED_SECRET_BSIZE] = [0; SHARED_SECRET_BSIZE];
    let local_secret = EphemeralSecret::new(OsRng);
    let local_public = PublicKey::from(&local_secret);
    let iv = gen_iv();

    unauth_stream.write(local_public.as_bytes())?;

    let len = unauth_stream.read(&mut buffer)?;
    assert_eq!(len, SHARED_SECRET_BSIZE);

    let remote_public = PublicKey::from(buffer);
    let shared_secret = local_secret.diffie_hellman(&remote_public);
    let shared_secret = shared_secret.to_bytes();

    Ok((unauth_stream, Session { key: shared_secret, iv, }))
}

fn gen_iv() -> [u8; BLOCK_BSIZE] {

    // FIXME This should be randomly generated per-session
    hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
}

pub fn encrypt(msg: &[u8], session: &Session)
               -> Result<Vec<u8>, Box<dyn Error>> {

    let cypherbox = Aes256Cbc::new_var(&session.key, &session.iv)?;

    let cyphertext = cypherbox.encrypt_vec(msg);
    Ok(cyphertext)
}

pub fn decrypt(msg: &[u8], session: &Session)
               -> Result<String, Box<dyn Error>> {

    let cypherbox = Aes256Cbc::new_var(&session.key, &session.iv)?;

    let plaintext = cypherbox.decrypt_vec(msg)?;
    let plaintext = String::from_utf8_lossy(&plaintext).to_string();
    Ok(plaintext)
}
