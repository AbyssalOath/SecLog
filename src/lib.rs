// This file makes the project usable as a LIBRARY, not just a binary.
// Any binary in this project (main.rs, or files under src/bin/) can now
// write 'use seclog::parser;' etc. to reach this shared code.
pub mod db;
pub mod models;
pub mod parser;
pub mod auth;
pub mod notify;
pub mod crypto;
pub mod directory;
pub mod syslog;
pub mod archive;
