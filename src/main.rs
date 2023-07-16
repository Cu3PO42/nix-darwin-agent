use std::ffi::{CString, CStr};
use std::io::Read;
use std::os::fd::{FromRawFd, AsRawFd};
use std::{io::Write, process::exit};

const ACCOUNT_NAME: &str = "Nix Store";

fn get_passphrase(uuid: &str) -> Result<Vec<u8>, security_framework::base::Error> {
    security_framework::passwords::get_generic_password(uuid, ACCOUNT_NAME)
}

fn mount_disk(uuid: &str, mountpoint: &str, passphrase: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new("/usr/sbin/diskutil")
        .arg("apfs")
        .arg("unlockVolume")
        .arg(uuid)
        .arg("-mountpoint")
        .arg(mountpoint)
        .arg("-stdinpassphrase")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = cmd.stdin.take() {
        stdin.write_all(passphrase)?;
    }
    cmd.wait()?;
    Ok(())
}

fn wait_for_binary(binary: &CStr) -> Result<(), std::io::Error> {
    // SAFETY: this is a POD-struct
    let mut stat_out: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the path is a valid CStr and the buffer was just allocated
    if unsafe { libc::stat(binary.as_ptr(), &mut stat_out) } == 0 {
        return Ok(());
    }

    // SAFETY: kqueue has no invariants to uphold
    let kq = unsafe { libc::kqueue() };
    if kq == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: we just opened the file and checked it is valid
    let kq = unsafe { std::os::fd::OwnedFd::from_raw_fd(kq) };

    let mut kernel_event = libc::kevent {
        ident: 0,
        filter: libc::EVFILT_FS,
        flags: libc::EV_ADD,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };

    // SAFETY:
    // - kq was created earlier
    // - changelist is not an array, but since nchanges = 1, we have just a single event
    // - eventlist is null, but we are not reading any
    // - timeout may be null
    if unsafe { libc::kevent(kq.as_raw_fd(), &kernel_event, 1, std::ptr::null_mut(), 0, std::ptr::null()) == -1 } {
        return Err(std::io::Error::last_os_error());
    }

    loop {
        // SAFETY:
        // - kq was created earlier
        // - changelist is null, but we aren't writing any
        // - eventlist is a pointer to one element and we are reading at most one
        // - timeout may be null
        unsafe { libc::kevent(kq.as_raw_fd(), std::ptr::null(), 0, &mut kernel_event, 1, std::ptr::null()) };
        // SAFETY: binary is a CStr, stat_out is allocated
        if unsafe { libc::stat(binary.as_ptr(), &mut stat_out) } == 0 {
            return Ok(());
        }
    }
}

fn exec_nix_daemon(binary: &CStr) -> Result<(), std::io::Error> {
    let argv = [binary.as_ptr() as *const libc::c_char, std::ptr::null()];
    // SAFETY: binary ends in a NULL byte because it is a CStr, argv also has an explicit NULL added
    if unsafe { libc::execv(argv[0], argv.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // We really want to return !, but the type is not yet stable
    Ok(())
}

fn install_key(uuid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut key = Vec::new();
    std::io::stdin().read_to_end(&mut key)?;
    security_framework::passwords::set_generic_password(uuid, ACCOUNT_NAME, &key)?;
    Ok(())
}

fn print_usage() {
    println!("Usage: nix-agent launch <disk-uuid> <nix-binary>");
    println!(" .     nix-agent install <disk-uuid>");
    println!("");
    println!("The install command accepts the passphrase on stdin.");
    exit(1);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    let _ = args.next(); // Drop the program name.

    match args.next() {
        Some(ref s) if s == "launch" => {
            if let (Some(uuid), Some(binary)) = (args.next(), args.next()) {
                let passphrase = get_passphrase(&uuid)?;
                mount_disk(&uuid, "/nix", &passphrase)?;
                
                let mut binary = binary.into_bytes();
                binary.push(0);
                // Should never fail: we have explicitly added a NUL at the end and the contents
                // prior are read from the OS args, which do not contain NUL-bytes on macOS
                let binary = CString::from_vec_with_nul(binary)?;

                wait_for_binary(&binary)?;
                exec_nix_daemon(&binary)?;
            } else {
                print_usage();
            }
        }
        Some(ref s) if s == "install" => {
            if let Some(uuid) = args.next() {
                install_key(&uuid)?;
            } else {
                print_usage();
            }
        }
        _ => {
            print_usage();
        }
    }
    Ok(())
}
