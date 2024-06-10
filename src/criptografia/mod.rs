#![allow(dead_code)]

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use aes_gcm::Nonce; 
use aes_gcm::aead::consts::U12;
use rand::RngCore;

pub fn encrypt(chave: &[u8; 32], senha_para_criptografar: &[u8]) -> (Vec<u8>, Vec<u8>) {
    //inicia a cifra AES-GCM com a chave fornecida
    let cifra = AesGcm::<Aes256, U12>::new_from_slice(chave).unwrap();
    //gera um nonce aleatório
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // Criptografa o dado
    let senha_criptografada = cifra.encrypt(Nonce::from_slice(&nonce), senha_para_criptografar)
        .expect("falha ao criptografar");
    //retorna uma tupla com o nonce e a senha criptografada
    (nonce.to_vec(), senha_criptografada)
}

//função para descriptografar
pub fn decrypt(chave: &[u8; 32], nonce: &[u8], senha_criptografada: &[u8]) -> Vec<u8> {
    // Inicializa a cifra AES-GCM com a chave fornecida
    let cifra = AesGcm::<Aes256, U12>::new_from_slice(chave).unwrap();

    // Descriptografa os dados
    let senha_descriptografada = cifra.decrypt(Nonce::from_slice(nonce), senha_criptografada)
        .expect("falha ao descriptografar");
    // retorna somente a senha descriptografada
    senha_descriptografada
}