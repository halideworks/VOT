use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

pub(super) type Owner = [u32; 17];
pub(super) struct Local(pub(super) *mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by a LocalAlloc-family security API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) fn current_owner() -> io::Result<Owner> {
    let mut token = std::ptr::null_mut();
    // SAFETY: the current thread pseudo-handle is valid and output storage is writable.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(i32::try_from(ERROR_NO_TOKEN).unwrap()) {
            return Err(error);
        }
        // SAFETY: the current process pseudo-handle is valid and output storage is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: a successful token open returns one owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut buffer = [0_usize; 32];
    let mut length = 0;
    // SAFETY: the aligned buffer exceeds TOKEN_USER plus the maximum 68-byte SID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of_val(&buffer)).unwrap(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut owner = [0_u32; 17];
    // SAFETY: successful TokenUser retrieval initializes this structure and its in-buffer SID.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: owner is aligned SID storage of SECURITY_MAX_SID_SIZE bytes.
    if unsafe { CopySid(68, owner.as_mut_ptr().cast(), sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owner)
}

pub(super) fn descriptor(owner: &Owner) -> io::Result<Local> {
    let mut sid = std::ptr::null_mut();
    // SAFETY: owner contains the initialized token SID; output is a LocalAlloc string.
    if unsafe { ConvertSidToStringSidW(owner.as_ptr().cast_mut().cast(), &raw mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _sid = Local(sid.cast());
    // SID text is bounded by the maximum SID subauthority count.
    let mut length = 0;
    while length < 256 {
        // SAFETY: the security API returned a terminated string; no reads occur after its NUL.
        if unsafe { *sid.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    if length == 256 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: length is the initialized UTF-16 string length, excluding NUL.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, length) })
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let sddl: Vec<_> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: sddl is terminated, and output storage receives an owned descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Local(descriptor))
}

pub(super) fn create(path: &Path) -> io::Result<()> {
    let descriptor = descriptor(&current_owner()?)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = parent.canonicalize()?.join(name);
    let mut path: Vec<_> = path.as_os_str().encode_wide().collect();
    if path.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    path.push(0);
    // SAFETY: the terminated path and initialized security descriptor outlive the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn set_test_acl(path: &Path, public: bool, inherit: bool) {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};
    let file = std::fs::OpenOptions::new()
        .access_mode(WRITE_DAC | READ_CONTROL)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    let descriptor = if public {
        let text: Vec<_> = "D:P(A;OICI;FA;;;WD)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut output = std::ptr::null_mut();
        assert_ne!(
            // SAFETY: the terminated SDDL and descriptor output remain valid throughout the call.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut output,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        Local(output)
    } else {
        descriptor(&current_owner().unwrap()).unwrap()
    };
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    assert_ne!(
        // SAFETY: descriptor owns the security descriptor and receives its interior ACL pointer.
        unsafe {
            GetSecurityDescriptorDacl(
                descriptor.0,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        },
        0
    );
    assert_ne!(present, 0);
    if !inherit {
        // SAFETY: dacl points into the live descriptor returned by the security API.
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ace = std::ptr::null_mut();
            // SAFETY: index is within the ACL and every ACE starts with this header.
            unsafe {
                assert_ne!(GetAce(dacl, u32::from(index), &raw mut ace), 0);
                (*ace.cast::<ACE_HEADER>()).AceFlags = 0;
            }
        }
    }
    assert_eq!(
        // SAFETY: the held handle has WRITE_DAC and the descriptor retains the provided ACL.
        unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        },
        0
    );
}

pub(super) fn check(file: &File, owner: &Owner, private: bool) -> io::Result<()> {
    let mut actual_owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: output pointers receive portions of the returned owned security descriptor.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut actual_owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
            result.to_ne_bytes(),
        )));
    }
    let _descriptor = Local(descriptor);
    let expected = owner.as_ptr().cast_mut().cast();
    // SAFETY: both non-null SIDs come from successful native security queries.
    if actual_owner.is_null() || dacl.is_null() || unsafe { EqualSid(expected, actual_owner) } == 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // SAFETY: dacl references the initialized ACL in descriptor, retained for this loop.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..count {
        let mut ace = std::ptr::null_mut();
        // SAFETY: index is within the ACL's initialized ACE count.
        if unsafe { GetAce(dacl, u32::from(index), &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE begins with ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == 1 {
            continue;
        } // ACCESS_DENIED_ACE cannot grant access.
        if header.AceType != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // SAFETY: type and size establish the standard access-allowed ACE layout.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        // SAFETY: sid addresses the native ACE's validated SID, and expected is retained.
        let trusted = unsafe {
            EqualSid(sid, expected) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        };
        let writes = FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | FILE_DELETE_CHILD
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | 0x1000_0000
            | 0x4000_0000;
        if !trusted && allowed.Mask & if private { u32::MAX } else { writes } != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(())
}
