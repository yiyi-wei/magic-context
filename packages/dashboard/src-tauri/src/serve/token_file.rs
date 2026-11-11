//! Optional stable bearer token for serve mode.
//!
//! By default every `--serve` process generates a fresh random token. A user who
//! wants a bookmarkable URL can create `dashboard-token` in the Magic Context
//! storage directory themselves. The file is honoured only when it is opened
//! without following a symlink, is a regular file, is owner-only (Unix: owned
//! by the current user with mode exactly `0600`; Windows: owned by the current
//! user and accessible only to that user, SYSTEM and Administrators), and its
//! trimmed contents are a URL-safe token of `MIN_TOKEN_LEN..=MAX_TOKEN_LEN`
//! characters. Anything else is ignored with a warning that names the failed
//! check and never the contents, and the process keeps the random token.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const TOKEN_FILE_NAME: &str = "dashboard-token";
pub const MIN_TOKEN_LEN: usize = 32;
pub const MAX_TOKEN_LEN: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum TokenFile {
    /// No file at the path: keep today's per-process random token.
    Missing,
    /// The file passed every check.
    Loaded(String),
    /// The file exists but was refused; the reason is safe to print.
    Rejected(&'static str),
}

/// `dashboard-token` in the storage directory the plugin uses on every platform,
/// resolved in the plugin's order (packages/plugin/src/shared/data-path.ts):
/// `MAGIC_CONTEXT_STORAGE_DIR`, then `<XDG_DATA_HOME>/cortexkit/magic-context`,
/// then `~/.local/share/cortexkit/magic-context`. Blank values count as unset,
/// matching the plugin's trim and the shell's `${XDG_DATA_HOME:-...}`. `None`
/// when no absolute path can be formed (including a relative
/// `MAGIC_CONTEXT_STORAGE_DIR`, which the plugin refuses too), so the token is
/// never read relative to the working directory.
pub fn default_token_path() -> Option<PathBuf> {
    token_path_from(
        std::env::var_os("MAGIC_CONTEXT_STORAGE_DIR"),
        std::env::var_os("XDG_DATA_HOME"),
        dirs::home_dir(),
    )
}

fn token_path_from(
    storage_dir: Option<OsString>,
    xdg_data_home: Option<OsString>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    let non_blank = |value: OsString| -> Option<PathBuf> {
        match value.to_str() {
            Some(text) => Some(text.trim())
                .filter(|t| !t.is_empty())
                .map(PathBuf::from),
            None => Some(PathBuf::from(value)),
        }
    };
    let dir = match storage_dir.and_then(non_blank) {
        Some(explicit) => explicit,
        None => xdg_data_home
            .and_then(non_blank)
            .or_else(|| home.map(|home| home.join(".local").join("share")))?
            .join("cortexkit")
            .join("magic-context"),
    };
    let path = dir.join(TOKEN_FILE_NAME);
    path.is_absolute().then_some(path)
}

pub fn read_token_file(path: &Path) -> TokenFile {
    match read_raw(path) {
        Ok(None) => TokenFile::Missing,
        Ok(Some(bytes)) => match validate_contents(&bytes) {
            Ok(token) => TokenFile::Loaded(token),
            Err(reason) => TokenFile::Rejected(reason),
        },
        Err(reason) => TokenFile::Rejected(reason),
    }
}

fn validate_contents(bytes: &[u8]) -> Result<String, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "it is not valid UTF-8")?;
    // Windows editors may save UTF-8 with a byte-order mark.
    let token = text.strip_prefix('\u{feff}').unwrap_or(text).trim();
    if token.is_empty() {
        return Err("it is empty");
    }
    // Unreserved URL characters only: the token travels in the `#token=` fragment
    // (decoded with decodeURIComponent and split on `&`) and in a Bearer header.
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err("it may only contain letters, digits, '-', '.', '_' and '~'");
    }
    if token.len() < MIN_TOKEN_LEN {
        return Err("it must be at least 32 characters long");
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err("it must be at most 512 characters long");
    }
    Ok(token.to_string())
}

/// Reads at most this many bytes, so a huge or endless file cannot stall startup.
#[cfg(any(unix, windows))]
const READ_LIMIT: u64 = 4096;

/// Reads the already-validated handle, never the path again, so the checks and
/// the read are on the same file.
#[cfg(any(unix, windows))]
fn read_limited(file: std::fs::File) -> Result<Option<Vec<u8>>, &'static str> {
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(READ_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "it could not be read")?;
    if bytes.len() as u64 > READ_LIMIT {
        return Err("it is larger than 4 KiB");
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn read_raw(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = match OpenOptions::new()
        .read(true)
        // O_NOFOLLOW refuses a symlink at the final component; O_NONBLOCK keeps a
        // FIFO planted at the path from blocking startup before the type check.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Err("it is a symlink");
        }
        Err(_) => return Err("it could not be opened"),
    };
    let metadata = file.metadata().map_err(|_| "it could not be inspected")?;
    if !metadata.file_type().is_file() {
        return Err("it is not a regular file");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("it is not owned by the current user");
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err("it must have owner-only permissions (0600)");
    }
    read_limited(file)
}

/// Windows has no mode bits; the equivalent guarantee comes from the file's
/// security descriptor, read from the open handle (see `windows_acl`).
#[cfg(windows)]
fn read_raw(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, READ_CONTROL,
    };

    let file = match OpenOptions::new()
        // Only what the checks need: FILE_READ_DATA for the contents,
        // FILE_READ_ATTRIBUTES for std's metadata(), READ_CONTROL for
        // GetSecurityInfo below. CreateFileW still adds SYNCHRONIZE for a
        // synchronous handle, so an entry that denies it (`deny write` does)
        // refuses the open; that is reported as access denied, never trusted.
        .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL)
        // Opens a symlink or junction itself instead of its target.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        // Without backup semantics a directory cannot be opened; name it anyway.
        Err(_) if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) => {
            return Err("it is not a regular file");
        }
        Err(err) if err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            return Err("access to it was denied");
        }
        Err(_) => return Err("it could not be opened"),
    };
    let metadata = file.metadata().map_err(|_| "it could not be inspected")?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("it is a symlink or other reparse point");
    }
    if !metadata.is_file() {
        return Err("it is not a regular file");
    }
    windows_acl::check_owner_only(&file)?;
    read_limited(file)
}

#[cfg(not(any(unix, windows)))]
fn read_raw(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    // No owner-only check is implemented here, so the file is refused rather
    // than trusted.
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err("owner-only permissions cannot be verified on this platform"),
        Err(_) => Ok(None),
    }
}

/// The Windows rule for "owner-only": the file's owner is the current user (or
/// SYSTEM / Administrators, which is what an elevated process assigns), the
/// DACL exists, and every ACE that grants anything grants it to the current
/// user, SYSTEM or BUILTIN\Administrators. Deny ACEs only take access away and
/// inherit-only ACEs do not apply to a file, so both are skipped; any other ACE
/// type (callback, object, conditional) is refused because it cannot be judged
/// here. A file created normally under the user profile inherits exactly this
/// shape (user, SYSTEM, Administrators).
#[cfg(windows)]
mod windows_acl {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) const NOT_OWNER: &str = "it is not owned by the current user";
    pub(super) const NULL_DACL: &str = "it has no access list, so every user can read it";
    pub(super) const OTHER_USERS: &str =
        "other users can access it (only you, SYSTEM and Administrators may)";
    pub(super) const UNKNOWN_ACE: &str = "its access list has entries that cannot be verified";
    const UNREADABLE: &str = "its access list could not be read";

    /// Frees a security descriptor returned by GetSecurityInfo.
    struct LocalBox(PSECURITY_DESCRIPTOR);
    impl Drop for LocalBox {
        fn drop(&mut self) {
            // SAFETY: the pointer came from GetSecurityInfo, which documents
            // LocalFree as its release function; it is freed exactly once.
            unsafe { LocalFree(self.0 as _) };
        }
    }

    pub(super) fn check_owner_only(file: &std::fs::File) -> Result<(), &'static str> {
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the handle is open with READ_CONTROL for the duration of the
        // call, and every out pointer refers to a live local.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(UNREADABLE);
        }
        // `owner` and `dacl` point into `descriptor`, which lives until here.
        let _descriptor = LocalBox(descriptor);
        let user = current_user()?;
        // SAFETY: owner/dacl point into the live descriptor; user.sid() points
        // into the live token buffer.
        unsafe { evaluate(owner, dacl, user.sid()) }
    }

    /// The TOKEN_USER of this process, kept in a u64 buffer for alignment.
    struct CurrentUser(Vec<u64>);
    impl CurrentUser {
        fn sid(&self) -> PSID {
            // SAFETY: the buffer was filled by GetTokenInformation(TokenUser).
            unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
        }
    }

    fn current_user() -> Result<CurrentUser, &'static str> {
        // SAFETY: standard token query; the handle is closed on every path and
        // the buffer is sized by the first call.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(UNREADABLE);
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buffer = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut c_void,
                (buffer.len() * 8) as u32,
                &mut len,
            );
            CloseHandle(token);
            if ok == 0 {
                return Err(UNREADABLE);
            }
            Ok(CurrentUser(buffer))
        }
    }

    unsafe fn trusted(sid: PSID, user: PSID) -> bool {
        EqualSid(sid, user) != 0
            || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }

    unsafe fn evaluate(owner: PSID, dacl: *mut ACL, user: PSID) -> Result<(), &'static str> {
        if owner.is_null() || !trusted(owner, user) {
            return Err(NOT_OWNER);
        }
        if dacl.is_null() {
            return Err(NULL_DACL);
        }
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            dacl,
            &mut info as *mut ACL_SIZE_INFORMATION as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return Err(UNREADABLE);
        }
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
                return Err(UNREADABLE);
            }
            let header = &*(ace as *const ACE_HEADER);
            if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            match u32::from(header.AceType) {
                ACCESS_DENIED_ACE_TYPE => {}
                ACCESS_ALLOWED_ACE_TYPE => {
                    let allowed = ace as *const ACCESS_ALLOWED_ACE;
                    // The SID runs past the 4-byte SidStart field, so derive the
                    // pointer from the ACE itself rather than from a reference.
                    let sid = std::ptr::addr_of!((*allowed).SidStart) as PSID;
                    if (*allowed).Mask != 0 && !trusted(sid, user) {
                        return Err(OTHER_USERS);
                    }
                }
                _ => return Err(UNKNOWN_ACE),
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    const GOOD: &str = "Abcdefghijklmnopqrstuvwxyz0123456789-._~";

    fn write_with_mode(path: &Path, contents: &[u8], mode: u32) {
        // Remove first: a previous case may have left the file read-only.
        let _ = fs::remove_file(path);
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn missing_file_keeps_random_token() {
        let dir = tempdir().unwrap();
        assert_eq!(
            read_token_file(&dir.path().join(TOKEN_FILE_NAME)),
            TokenFile::Missing
        );
    }

    #[test]
    fn owner_only_file_is_loaded_and_trimmed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        write_with_mode(&path, format!("  {GOOD}\n").as_bytes(), 0o600);
        assert_eq!(read_token_file(&path), TokenFile::Loaded(GOOD.to_string()));
    }

    #[test]
    fn group_or_world_readable_file_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        for mode in [0o640, 0o644, 0o604, 0o400, 0o700] {
            write_with_mode(&path, GOOD.as_bytes(), mode);
            assert_eq!(
                read_token_file(&path),
                TokenFile::Rejected("it must have owner-only permissions (0600)"),
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn symlink_is_refused_even_to_an_owner_only_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real-token");
        write_with_mode(&target, GOOD.as_bytes(), 0o600);
        let link = dir.path().join(TOKEN_FILE_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            read_token_file(&link),
            TokenFile::Rejected("it is a symlink")
        );
    }

    #[test]
    fn directory_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_token_file(&path),
            TokenFile::Rejected("it is not a regular file")
        );
    }

    #[test]
    fn fifo_is_refused_without_blocking() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            read_token_file(&path),
            TokenFile::Rejected("it is not a regular file")
        );
    }

    #[test]
    fn short_empty_or_oversized_contents_are_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        let cases: [(Vec<u8>, &str); 5] = [
            (b"\n  \n".to_vec(), "it is empty"),
            (
                vec![b'a'; MIN_TOKEN_LEN - 1],
                "it must be at least 32 characters long",
            ),
            (
                vec![b'a'; MAX_TOKEN_LEN + 1],
                "it must be at most 512 characters long",
            ),
            (
                vec![b'a'; READ_LIMIT as usize + 1],
                "it is larger than 4 KiB",
            ),
            (vec![0xff; MIN_TOKEN_LEN], "it is not valid UTF-8"),
        ];
        for (contents, reason) in cases {
            write_with_mode(&path, &contents, 0o600);
            assert_eq!(read_token_file(&path), TokenFile::Rejected(reason));
        }
    }

    #[test]
    fn characters_that_break_the_url_fragment_are_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        for bad in ["&", "%", "#", "=", " ", "+", "/", "é"] {
            let token = format!("{}{bad}{}", "a".repeat(20), "b".repeat(20));
            write_with_mode(&path, token.as_bytes(), 0o600);
            assert_eq!(
                read_token_file(&path),
                TokenFile::Rejected("it may only contain letters, digits, '-', '.', '_' and '~'"),
                "char {bad:?}"
            );
        }
    }

    #[test]
    fn exact_length_bounds_are_accepted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        for len in [MIN_TOKEN_LEN, MAX_TOKEN_LEN] {
            let token = "x".repeat(len);
            write_with_mode(&path, token.as_bytes(), 0o600);
            assert_eq!(read_token_file(&path), TokenFile::Loaded(token));
        }
    }
}

#[cfg(test)]
mod content_tests {
    use super::*;

    fn abs(tail: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{tail}"))
        } else {
            PathBuf::from(format!("/{tail}"))
        }
    }

    fn os(path: &Path) -> Option<OsString> {
        Some(path.as_os_str().to_owned())
    }

    #[test]
    fn storage_dir_override_wins_like_the_plugin() {
        let store = abs("store");
        assert_eq!(
            token_path_from(os(&store), os(&abs("xdg")), Some(abs("home"))),
            Some(store.join(TOKEN_FILE_NAME))
        );
    }

    #[test]
    fn relative_storage_dir_override_is_not_used() {
        assert_eq!(
            token_path_from(Some("rel".into()), os(&abs("xdg")), Some(abs("home"))),
            None
        );
    }

    #[test]
    fn xdg_then_home_when_no_override() {
        let tail = |base: PathBuf| {
            base.join("cortexkit")
                .join("magic-context")
                .join(TOKEN_FILE_NAME)
        };
        assert_eq!(
            token_path_from(Some("  ".into()), os(&abs("xdg")), Some(abs("home"))),
            Some(tail(abs("xdg")))
        );
        assert_eq!(
            token_path_from(None, Some("".into()), Some(abs("home"))),
            Some(tail(abs("home").join(".local").join("share")))
        );
        assert_eq!(token_path_from(None, None, None), None);
    }

    #[test]
    fn utf8_byte_order_mark_is_ignored() {
        let token = "x".repeat(MIN_TOKEN_LEN);
        assert_eq!(
            validate_contents(format!("\u{feff}{token}\r\n").as_bytes()),
            Ok(token)
        );
    }
}

/// Windows cases build each access list from SDDL and apply it to the file with
/// a protected DACL, so the result does not depend on what the temp directory
/// happens to inherit. Run on a real Windows host (see the PR for the CI run).
#[cfg(all(test, windows))]
mod windows_tests {
    use super::windows_acl::{NOT_OWNER, NULL_DACL, OTHER_USERS, UNKNOWN_ACE};
    use super::*;
    use std::ffi::c_void;
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use tempfile::tempdir;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const GOOD: &str = "Abcdefghijklmnopqrstuvwxyz0123456789-._~";
    const REPARSE: &str = "it is a symlink or other reparse point";

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// `S-1-5-21-...` of the user running the tests.
    fn user_sid() -> String {
        unsafe {
            let mut token = null_mut();
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
                0
            );
            let mut buffer = vec![0u64; 64];
            let mut len = 0u32;
            assert_ne!(
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr() as *mut c_void,
                    (buffer.len() * 8) as u32,
                    &mut len,
                ),
                0
            );
            let sid = (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid;
            let mut text = null_mut();
            assert_ne!(ConvertSidToStringSidW(sid, &mut text), 0);
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let out = String::from_utf16(std::slice::from_raw_parts(text, len)).unwrap();
            LocalFree(text as _);
            out
        }
    }

    /// Replaces the file's DACL with the one in `sddl` (e.g. `D:P(A;;FA;;;SY)`),
    /// protected from inheritance. `D:NO_ACCESS_CONTROL` gives a NULL DACL.
    fn set_dacl(path: &Path, sddl: &str) {
        unsafe {
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            let sddl = wide(std::ffi::OsStr::new(sddl));
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                ),
                0,
                "bad SDDL"
            );
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = null_mut();
            assert_ne!(
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted),
                0
            );
            assert_ne!(present, 0);
            let status = SetNamedSecurityInfoW(
                wide(path.as_os_str()).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            );
            LocalFree(descriptor as _);
            assert_eq!(status, ERROR_SUCCESS, "SetNamedSecurityInfoW");
        }
    }

    fn token_file_with_dacl(dir: &Path, sddl: &str) -> std::path::PathBuf {
        let path = dir.join(TOKEN_FILE_NAME);
        fs::write(&path, GOOD).unwrap();
        set_dacl(&path, sddl);
        path
    }

    #[test]
    fn missing_file_keeps_random_token() {
        let dir = tempdir().unwrap();
        assert_eq!(
            read_token_file(&dir.path().join(TOKEN_FILE_NAME)),
            TokenFile::Missing
        );
    }

    /// What a user gets from creating the file in their profile with no extra
    /// steps: inherited access for the user, SYSTEM and Administrators.
    #[test]
    fn file_created_with_inherited_profile_acl_is_loaded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        fs::write(&path, format!("{GOOD}\r\n")).unwrap();
        assert_eq!(read_token_file(&path), TokenFile::Loaded(GOOD.to_string()));
    }

    #[test]
    fn user_system_and_administrators_only_is_loaded() {
        let dir = tempdir().unwrap();
        let user = user_sid();
        for sddl in [
            format!("D:P(A;;FA;;;{user})"),
            format!("D:P(A;;FA;;;{user})(A;;FA;;;SY)(A;;FA;;;BA)"),
        ] {
            let path = token_file_with_dacl(dir.path(), &sddl);
            assert_eq!(
                read_token_file(&path),
                TokenFile::Loaded(GOOD.to_string()),
                "{sddl}"
            );
        }
    }

    /// A deny entry takes access away, so it is never read as a grant. With
    /// `deny write` the open is refused first: FILE_GENERIC_WRITE contains
    /// SYNCHRONIZE, which CreateFileW requests for every synchronous handle.
    #[test]
    fn deny_write_entry_refuses_the_open() {
        let dir = tempdir().unwrap();
        let sddl = format!("D:P(D;;FW;;;WD)(A;;FA;;;{})", user_sid());
        let path = token_file_with_dacl(dir.path(), &sddl);
        assert_eq!(
            read_token_file(&path),
            TokenFile::Rejected("access to it was denied"),
            "{sddl}"
        );
    }

    /// A deny entry that leaves the open's access alone is skipped: it only
    /// takes access away, so the file stays owner-only and is used.
    #[test]
    fn deny_entry_outside_the_open_is_skipped() {
        let dir = tempdir().unwrap();
        // WD = WRITE_DAC: denies nothing the open asks for.
        let sddl = format!("D:P(D;;WD;;;WD)(A;;FA;;;{})", user_sid());
        let path = token_file_with_dacl(dir.path(), &sddl);
        assert_eq!(
            read_token_file(&path),
            TokenFile::Loaded(GOOD.to_string()),
            "{sddl}"
        );
    }

    #[test]
    fn access_for_anyone_else_is_refused() {
        let dir = tempdir().unwrap();
        let user = user_sid();
        // Everyone, Authenticated Users, Users, Guests, another account.
        for other in ["WD", "AU", "BU", "BG", "S-1-5-21-1-2-3-1001"] {
            let sddl = format!("D:P(A;;FA;;;{user})(A;;FR;;;{other})");
            let path = token_file_with_dacl(dir.path(), &sddl);
            assert_eq!(
                read_token_file(&path),
                TokenFile::Rejected(OTHER_USERS),
                "{sddl}"
            );
        }
    }

    #[test]
    fn null_dacl_is_refused() {
        let dir = tempdir().unwrap();
        let path = token_file_with_dacl(dir.path(), "D:NO_ACCESS_CONTROL");
        assert_eq!(read_token_file(&path), TokenFile::Rejected(NULL_DACL));
    }

    #[test]
    fn conditional_entry_is_refused() {
        let dir = tempdir().unwrap();
        let user = user_sid();
        let sddl = format!("D:P(A;;FA;;;{user})(XA;;FR;;;WD;(Member_of {{SID(BA)}}))");
        let path = token_file_with_dacl(dir.path(), &sddl);
        assert_eq!(read_token_file(&path), TokenFile::Rejected(UNKNOWN_ACE));
    }

    /// Changing the owner to another principal needs SeRestorePrivilege, which
    /// `icacls /setowner` enables for an elevated caller (CI runners are).
    #[test]
    fn file_owned_by_another_principal_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        fs::write(&path, GOOD).unwrap();
        let status = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/setowner", "*S-1-5-32-545"])
            .status()
            .unwrap();
        assert!(status.success(), "icacls /setowner needs an elevated shell");
        assert_eq!(read_token_file(&path), TokenFile::Rejected(NOT_OWNER));
    }

    /// Needs the symlink privilege (elevated shell or Developer Mode).
    #[test]
    fn symlink_is_refused_even_to_a_good_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real-token");
        fs::write(&target, GOOD).unwrap();
        let link = dir.path().join(TOKEN_FILE_NAME);
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        assert_eq!(
            read_token_file(&target),
            TokenFile::Loaded(GOOD.to_string())
        );
        assert_eq!(read_token_file(&link), TokenFile::Rejected(REPARSE));
    }

    #[test]
    fn directory_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        fs::create_dir(&path).unwrap();
        assert_eq!(
            read_token_file(&path),
            TokenFile::Rejected("it is not a regular file")
        );
    }

    #[test]
    fn bad_contents_are_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        fs::write(&path, "short").unwrap();
        assert_eq!(
            read_token_file(&path),
            TokenFile::Rejected("it must be at least 32 characters long")
        );
        fs::write(&path, vec![b'a'; READ_LIMIT as usize + 1]).unwrap();
        assert_eq!(
            read_token_file(&path),
            TokenFile::Rejected("it is larger than 4 KiB")
        );
    }
}
