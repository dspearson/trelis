//! Memory locking to prevent secrets from being swapped to disc.
//!
//! This module provides OS-level memory protection for sensitive cryptographic
//! material. When enabled, secrets are locked into physical RAM and cannot be
//! swapped to disc, protecting against cold boot attacks and swap file forensics.
//!
//! # Platform Support
//!
//! | Platform | API | Notes |
//! |----------|-----|-------|
//! | Linux | `mlock(2)` | Requires `CAP_IPC_LOCK` or sufficient `RLIMIT_MEMLOCK` |
//! | macOS | `mlock(2)` | Works without special privileges |
//! | FreeBSD | `mlock(2)` | May require privilege |
//! | Windows | `VirtualLock` | Requires `SE_LOCK_MEMORY_NAME` privilege |
//!
//! # Security Model
//!
//! Memory locking provides protection against:
//! - **Swap file forensics**: Secrets never written to swap partition
//! - **Cold boot attacks**: RAM contents harder to recover after power loss
//! - **Hibernation leaks**: Locked pages excluded from hibernation image
//!
//! Memory locking does NOT protect against:
//! - **Root access**: A privileged attacker can still read process memory
//! - **Core dumps**: Use `prctl(PR_SET_DUMPABLE, 0)` separately
//! - **ptrace**: Disable with `prctl(PR_SET_DUMPABLE, 0)`
//!
//! # Status in the Trelis Workspace
//!
//! As of the v1.0 security audit, this infrastructure is **opt-in and not
//! wired into any default code path**. Identity keypairs, session
//! root keys, and KEM keypairs are stored in ordinary heap allocations. Every
//! secret type still guarantees zeroize-on-drop, but **swap-file and core-dump
//! exclusion are not provided by default** — they are a caller / platform
//! responsibility.
//!
//! Consumers with a high-value-secret threat model should enable the `mlock`
//! feature and call `into_guarded()` (available on `HybridSigningKeypair`,
//! `HybridKemKeypair`, and the standalone signing-key types) for long-lived
//! keypairs at session establishment. Forcing `mlock` on by default would
//! impose `RLIMIT_MEMLOCK` / `CAP_IPC_LOCK` constraints on every consumer of
//! what is a general-purpose library, so the wiring is deliberately deferred.
//!
//! # Usage
//!
//! ```ignore
//! use trelis_primitives::memlock::{LockedBox, lock_memory, MemlockError};
//!
//! // Option 1: Use LockedBox for automatic lock/unlock lifecycle
//! let secret_key = LockedBox::new([0u8; 32])?;
//! // Memory is locked, use secret_key.as_ref() to access
//! // Automatically unlocked and zeroised on drop
//!
//! // Option 2: Manual lock/unlock for existing allocations
//! let mut buffer = vec![0u8; 4096];
//! lock_memory(buffer.as_ptr(), buffer.len())?;
//! // ... use buffer ...
//! unlock_memory(buffer.as_ptr(), buffer.len())?;
//! ```
//!
//! # Resource Limits
//!
//! Most systems limit the amount of memory a process can lock:
//!
//! ```bash
//! # Check current limit
//! ulimit -l
//!
//! # Increase limit (root or /etc/security/limits.conf)
//! ulimit -l unlimited
//! ```
//!
//! # Feature Flag
//!
//! This module requires the `mlock` feature:
//!
//! ```toml
//! [dependencies]
//! trelis-primitives = { version = "0.1", features = ["mlock"] }
//! ```

// SAFETY: This module contains the ONLY unsafe code in trelis-primitives.
// All unsafe operations are:
// 1. FFI calls to well-defined OS APIs (mlock, munlock, VirtualLock, VirtualUnlock)
// 2. Pointer arithmetic on valid, owned memory
// 3. Carefully audited and documented
//
// The rest of the crate uses #![forbid(unsafe_code)] which this module overrides.
#![allow(unsafe_code)]
// memlock is an FFI wrapper around mlock(2) / VirtualLock. Pedantic
// warnings here are dominated by FFI-shape calls (cast_lossless on
// length-as-c-size_t, pointer-shape conversions to `*const c_void`, paired
// lock/unlock identifiers, must_use on side-effectful FFI helpers) where
// mechanical rewrites do not improve clarity.
#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::ptr_as_ptr,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::uninlined_format_args
)]

extern crate std;

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use std::alloc::{Layout, alloc, dealloc};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during memory locking operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemlockError {
    /// Memory locking failed (insufficient privileges or resource limits).
    LockFailed {
        /// OS error code (errno on Unix, GetLastError on Windows).
        os_error: i32,
    },
    /// Memory unlocking failed.
    UnlockFailed {
        /// OS error code.
        os_error: i32,
    },
    /// Memory protection change failed (mprotect/VirtualProtect).
    ProtectFailed {
        /// OS error code.
        os_error: i32,
    },
    /// Memory allocation failed.
    AllocationFailed,
    /// The requested size is zero or too large.
    InvalidSize,
    /// Platform does not support memory locking.
    NotSupported,
}

impl fmt::Display for MemlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFailed { os_error } => {
                write!(f, "memory lock failed (os error: {os_error})")
            }
            Self::UnlockFailed { os_error } => {
                write!(f, "memory unlock failed (os error: {os_error})")
            }
            Self::ProtectFailed { os_error } => {
                write!(f, "memory protection change failed (os error: {os_error})")
            }
            Self::AllocationFailed => write!(f, "memory allocation failed"),
            Self::InvalidSize => write!(f, "invalid size for memory locking"),
            Self::NotSupported => write!(f, "memory locking not supported on this platform"),
        }
    }
}

impl std::error::Error for MemlockError {}

/// Result type for memory locking operations.
pub type Result<T> = core::result::Result<T, MemlockError>;

// ============================================================================
// Platform-specific implementations
// ============================================================================

/// Locks memory pages into RAM, preventing them from being swapped to disk.
///
/// # Safety Requirements (internal)
///
/// The caller must ensure:
/// - `ptr` points to valid, allocated memory
/// - `len` bytes starting at `ptr` are within the allocation
/// - The memory remains allocated until `unlock_memory` is called
///
/// # Arguments
///
/// * `ptr` - Pointer to the start of the memory region
/// * `len` - Length of the memory region in bytes
///
/// # Errors
///
/// Returns `MemlockError::LockFailed` if:
/// - Insufficient privileges (need `CAP_IPC_LOCK` on Linux)
/// - Resource limit exceeded (`RLIMIT_MEMLOCK`)
/// - Invalid memory region
///
/// # Example
///
/// ```ignore
/// let mut secret = [0u8; 32];
/// lock_memory(secret.as_ptr(), secret.len())?;
/// // ... use secret ...
/// unlock_memory(secret.as_ptr(), secret.len())?;
/// ```
#[cfg(unix)]
pub fn lock_memory(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // SAFETY: We're calling mlock with a valid pointer and length.
    // The caller guarantees the memory is valid and owned.
    let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };

    if result == 0 {
        Ok(())
    } else {
        // Use std::io::Error for portable errno access (works on Linux, macOS, illumos, BSDs)
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MemlockError::LockFailed { os_error: errno })
    }
}

/// Unlocks previously locked memory pages.
///
/// # Arguments
///
/// * `ptr` - Pointer to the start of the memory region
/// * `len` - Length of the memory region in bytes
///
/// # Errors
///
/// Returns `MemlockError::UnlockFailed` if the memory was not locked or
/// the parameters don't match the original lock.
#[cfg(unix)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // SAFETY: We're calling munlock with a valid pointer and length.
    let result = unsafe { libc::munlock(ptr as *const libc::c_void, len) };

    if result == 0 {
        Ok(())
    } else {
        // Use std::io::Error for portable errno access (works on Linux, macOS, illumos, BSDs)
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MemlockError::UnlockFailed { os_error: errno })
    }
}

/// Returns the system page size in bytes.
#[cfg(unix)]
pub fn page_size() -> usize {
    // SAFETY: sysconf is safe to call with _SC_PAGESIZE
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        4096 // Fallback to common page size
    } else {
        size as usize
    }
}

/// Advise the kernel that this memory contains secrets (Linux-specific).
///
/// On Linux 5.14+, this uses `madvise(MADV_DONTDUMP)` to exclude the memory
/// from core dumps.
#[cfg(target_os = "linux")]
pub fn advise_secret(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // MADV_DONTDUMP = 16 (exclude from core dump)
    const MADV_DONTDUMP: libc::c_int = 16;

    // SAFETY: madvise with MADV_DONTDUMP is safe for valid memory regions
    let result = unsafe { libc::madvise(ptr as *mut libc::c_void, len, MADV_DONTDUMP) };

    if result == 0 {
        Ok(())
    } else {
        // Non-fatal: older kernels may not support MADV_DONTDUMP
        Ok(())
    }
}

/// Advises the kernel that memory contains secrets (non-Linux Unix stub).
///
/// This is a no-op on non-Linux Unix platforms (macOS, FreeBSD, etc.)
/// as they don't support `MADV_DONTDUMP`. The memory will still be
/// protected by `mlock()`.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn advise_secret(_ptr: *const u8, _len: usize) -> Result<()> {
    Ok(())
}

// ============================================================================
// Windows implementation
// ============================================================================

/// Locks memory pages into RAM on Windows using `VirtualLock`.
///
/// # Requirements
///
/// - Process must have sufficient working set quota
/// - May require `SE_LOCK_MEMORY_NAME` privilege for large allocations
///
/// # Errors
///
/// Returns `MemlockError::LockFailed` if:
/// - Insufficient working set quota
/// - Invalid memory region
/// - Privilege not held
#[cfg(windows)]
pub fn lock_memory(ptr: *const u8, len: usize) -> Result<()> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Memory::VirtualLock;

    if len == 0 {
        return Ok(());
    }

    // SAFETY: VirtualLock is safe to call with valid pointer and length.
    // The caller guarantees the memory is valid and owned.
    let result = unsafe { VirtualLock(ptr as *mut core::ffi::c_void, len) };

    if result != 0 {
        Ok(())
    } else {
        Err(MemlockError::LockFailed {
            os_error: unsafe { GetLastError() } as i32,
        })
    }
}

/// Unlocks previously locked memory pages on Windows.
#[cfg(windows)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> Result<()> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Memory::VirtualUnlock;

    if len == 0 {
        return Ok(());
    }

    // SAFETY: VirtualUnlock is safe to call with valid pointer and length.
    let result = unsafe { VirtualUnlock(ptr as *mut core::ffi::c_void, len) };

    if result != 0 {
        Ok(())
    } else {
        Err(MemlockError::UnlockFailed {
            os_error: unsafe { GetLastError() } as i32,
        })
    }
}

/// Returns the system page size in bytes on Windows.
#[cfg(windows)]
pub fn page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    // SAFETY: GetSystemInfo is safe to call with a valid SYSTEM_INFO pointer
    let mut info: SYSTEM_INFO = unsafe { core::mem::zeroed() };
    unsafe { GetSystemInfo(&mut info) };

    info.dwPageSize as usize
}

/// Windows equivalent of MADV_DONTDUMP - not directly available.
///
/// On Windows, we could use `SetProcessWorkingSetSizeEx` with
/// `QUOTA_LIMITS_HARDWS_MIN_DISABLE` but this affects the entire process.
/// For now, this is a no-op on Windows.
#[cfg(windows)]
pub fn advise_secret(_ptr: *const u8, _len: usize) -> Result<()> {
    // Windows doesn't have a direct equivalent to MADV_DONTDUMP.
    // Minidumps can be controlled at the process level via:
    // - MiniDumpWriteDump flags
    // - SetErrorMode
    // - Registry settings
    Ok(())
}

// ============================================================================
// Memory protection (mprotect) - Unix implementation
// ============================================================================

/// Sets memory region to read-only.
///
/// After calling this, any write attempt to the memory region will cause
/// a segmentation fault (SIGSEGV on Unix, access violation on Windows).
///
/// # Use Cases
///
/// - Protect cryptographic keys after initialisation
/// - Detect accidental writes to immutable data
/// - Defence-in-depth against buffer overflows
///
/// # Requirements
///
/// The memory region should be page-aligned for best results. Non-aligned
/// regions will have the protection applied to the containing pages.
///
/// # Errors
///
/// Returns `MemlockError::ProtectFailed` if the protection change fails.
#[cfg(unix)]
pub fn protect_readonly(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // SAFETY: mprotect with PROT_READ is safe for valid memory regions
    let result = unsafe { libc::mprotect(ptr as *mut libc::c_void, len, libc::PROT_READ) };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MemlockError::ProtectFailed { os_error: errno })
    }
}

/// Sets memory region to read-write.
///
/// This restores normal read-write access to a previously protected region.
/// Must be called before deallocating protected memory.
///
/// # Errors
///
/// Returns `MemlockError::ProtectFailed` if the protection change fails.
#[cfg(unix)]
pub fn protect_readwrite(ptr: *mut u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // SAFETY: mprotect with PROT_READ | PROT_WRITE is safe for valid memory regions
    let result = unsafe {
        libc::mprotect(
            ptr as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MemlockError::ProtectFailed { os_error: errno })
    }
}

/// Sets memory region to no-access (neither readable nor writable).
///
/// After calling this, any read or write attempt to the memory region will
/// cause a segmentation fault. This is used for guard pages.
///
/// # Use Cases
///
/// - Guard pages to detect buffer overflows/underflows
/// - Temporarily hiding sensitive data
///
/// # Errors
///
/// Returns `MemlockError::ProtectFailed` if the protection change fails.
#[cfg(unix)]
pub fn protect_noaccess(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // SAFETY: mprotect with PROT_NONE is safe for valid memory regions
    let result = unsafe { libc::mprotect(ptr as *mut libc::c_void, len, libc::PROT_NONE) };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MemlockError::ProtectFailed { os_error: errno })
    }
}

// ============================================================================
// Memory protection (mprotect) - Windows implementation
// ============================================================================

/// Sets memory region to read-only on Windows.
#[cfg(windows)]
pub fn protect_readonly(ptr: *const u8, len: usize) -> Result<()> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Memory::{PAGE_READONLY, VirtualProtect};

    if len == 0 {
        return Ok(());
    }

    let mut old_protect: u32 = 0;

    // SAFETY: VirtualProtect is safe for valid memory regions
    let result = unsafe {
        VirtualProtect(
            ptr as *mut core::ffi::c_void,
            len,
            PAGE_READONLY,
            &mut old_protect,
        )
    };

    if result != 0 {
        Ok(())
    } else {
        Err(MemlockError::ProtectFailed {
            os_error: unsafe { GetLastError() } as i32,
        })
    }
}

/// Sets memory region to read-write on Windows.
#[cfg(windows)]
pub fn protect_readwrite(ptr: *mut u8, len: usize) -> Result<()> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};

    if len == 0 {
        return Ok(());
    }

    let mut old_protect: u32 = 0;

    // SAFETY: VirtualProtect is safe for valid memory regions
    let result = unsafe {
        VirtualProtect(
            ptr as *mut core::ffi::c_void,
            len,
            PAGE_READWRITE,
            &mut old_protect,
        )
    };

    if result != 0 {
        Ok(())
    } else {
        Err(MemlockError::ProtectFailed {
            os_error: unsafe { GetLastError() } as i32,
        })
    }
}

/// Sets memory region to no-access on Windows.
#[cfg(windows)]
pub fn protect_noaccess(ptr: *const u8, len: usize) -> Result<()> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Memory::{PAGE_NOACCESS, VirtualProtect};

    if len == 0 {
        return Ok(());
    }

    let mut old_protect: u32 = 0;

    // SAFETY: VirtualProtect is safe for valid memory regions
    let result = unsafe {
        VirtualProtect(
            ptr as *mut core::ffi::c_void,
            len,
            PAGE_NOACCESS,
            &mut old_protect,
        )
    };

    if result != 0 {
        Ok(())
    } else {
        Err(MemlockError::ProtectFailed {
            os_error: unsafe { GetLastError() } as i32,
        })
    }
}

// ============================================================================
// Page-aligned allocation helpers
// ============================================================================

/// Rounds a size up to the nearest page boundary.
#[inline]
fn page_round(size: usize, page_size: usize) -> usize {
    (size + page_size - 1) & !(page_size - 1)
}

/// Allocates page-aligned memory.
///
/// Returns a pointer to the allocated memory and the actual allocated size.
/// The caller is responsible for deallocating with `page_aligned_free`.
#[cfg(unix)]
fn page_aligned_alloc(size: usize) -> Result<(*mut u8, usize)> {
    let ps = page_size();
    let aligned_size = page_round(size, ps);

    if aligned_size == 0 {
        return Err(MemlockError::InvalidSize);
    }

    let mut ptr: *mut libc::c_void = core::ptr::null_mut();

    // SAFETY: posix_memalign is safe with valid alignment (power of 2, multiple of sizeof(void*))
    let result = unsafe { libc::posix_memalign(&mut ptr, ps, aligned_size) };

    if result == 0 && !ptr.is_null() {
        Ok((ptr as *mut u8, aligned_size))
    } else {
        Err(MemlockError::AllocationFailed)
    }
}

/// Allocates page-aligned memory on Windows.
#[cfg(windows)]
fn page_aligned_alloc(size: usize) -> Result<(*mut u8, usize)> {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
    };

    let ps = page_size();
    let aligned_size = page_round(size, ps);

    if aligned_size == 0 {
        return Err(MemlockError::InvalidSize);
    }

    // SAFETY: VirtualAlloc with MEM_COMMIT | MEM_RESERVE allocates new memory
    let ptr = unsafe {
        VirtualAlloc(
            core::ptr::null(),
            aligned_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if !ptr.is_null() {
        Ok((ptr as *mut u8, aligned_size))
    } else {
        Err(MemlockError::AllocationFailed)
    }
}

/// Frees page-aligned memory allocated with `page_aligned_alloc`.
#[cfg(unix)]
unsafe fn page_aligned_free(ptr: *mut u8, _size: usize) {
    unsafe { libc::free(ptr as *mut libc::c_void) };
}

/// Frees page-aligned memory on Windows.
#[cfg(windows)]
unsafe fn page_aligned_free(ptr: *mut u8, _size: usize) {
    use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
    unsafe { VirtualFree(ptr as *mut core::ffi::c_void, 0, MEM_RELEASE) };
}

// ============================================================================
// LockedBox<T> - Smart pointer with automatic memory locking
// ============================================================================

/// A heap-allocated value with memory locked into RAM.
///
/// `LockedBox<T>` is similar to `Box<T>` but with additional security guarantees:
///
/// 1. **Memory locking**: The underlying memory is locked into RAM using `mlock(2)`,
///    preventing it from being swapped to disc.
///
/// 2. **Automatic zeroisation**: When dropped, the memory is securely zeroed before
///    being unlocked and deallocated.
///
/// 3. **Core dump exclusion**: On Linux, the memory is marked with `MADV_DONTDUMP`
///    to exclude it from core dumps.
///
/// # Type Constraints
///
/// `T` must implement:
/// - `Zeroize`: For secure memory clearing on drop
/// - `Sized`: For heap allocation
///
/// # Example
///
/// ```ignore
/// use trelis_primitives::memlock::LockedBox;
///
/// // Create a locked secret key
/// let secret_key: LockedBox<[u8; 32]> = LockedBox::new([0u8; 32])?;
///
/// // Access the value (still locked)
/// let key_ref: &[u8; 32] = &*secret_key;
///
/// // When dropped: zeroize → unlock → deallocate
/// drop(secret_key);
/// ```
///
/// # Failure Handling
///
/// If memory locking fails (e.g., insufficient privileges), `new()` returns an error
/// and the value is securely zeroised before returning. No partially-initialised
/// `LockedBox` can exist.
pub struct LockedBox<T: Zeroize> {
    ptr: NonNull<T>,
    layout: Layout,
    locked: bool,
    _marker: PhantomData<T>,
}

impl<T: Zeroize> LockedBox<T> {
    /// Creates a new `LockedBox` containing the given value.
    ///
    /// The value is moved to the heap, the memory is locked, and on Linux,
    /// marked to be excluded from core dumps.
    ///
    /// # Errors
    ///
    /// Returns `MemlockError::AllocationFailed` if heap allocation fails.
    /// Returns `MemlockError::LockFailed` if memory locking fails.
    ///
    /// In case of lock failure, the value is zeroised and deallocated.
    pub fn new(mut value: T) -> Result<Self> {
        let layout = Layout::new::<T>();

        if layout.size() == 0 {
            return Err(MemlockError::InvalidSize);
        }

        // Allocate memory
        // SAFETY: Layout is non-zero size (checked above)
        let ptr = unsafe { alloc(layout) as *mut T };

        if ptr.is_null() {
            // Zeroize the value before returning error
            value.zeroize();
            return Err(MemlockError::AllocationFailed);
        }

        // SAFETY: ptr is non-null and properly aligned for T
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        // Move value to allocated memory
        // SAFETY: ptr points to valid, uninitialised memory of correct size
        unsafe {
            core::ptr::write(ptr.as_ptr(), value);
        }

        // Try to lock the memory
        let lock_result = lock_memory(ptr.as_ptr() as *const u8, layout.size());

        // Try to advise kernel (non-fatal if fails)
        let _ = advise_secret(ptr.as_ptr() as *const u8, layout.size());

        match lock_result {
            Ok(()) => Ok(Self {
                ptr,
                layout,
                locked: true,
                _marker: PhantomData,
            }),
            Err(e) => {
                // Lock failed - zeroize and deallocate
                // SAFETY: ptr is valid and initialised
                unsafe {
                    (*ptr.as_ptr()).zeroize();
                    dealloc(ptr.as_ptr() as *mut u8, layout);
                }
                Err(e)
            }
        }
    }

    /// Creates a `LockedBox` without memory locking.
    ///
    /// This is useful when memory locking is not available or not required,
    /// but you still want the zeroisation-on-drop guarantee.
    ///
    /// # Security Note
    ///
    /// Without memory locking, the secret may be swapped to disc. Use this
    /// only when `new()` fails or for non-critical secrets.
    pub fn new_unlocked(value: T) -> Result<Self> {
        let layout = Layout::new::<T>();

        if layout.size() == 0 {
            return Err(MemlockError::InvalidSize);
        }

        // SAFETY: Layout is non-zero size
        let ptr = unsafe { alloc(layout) as *mut T };

        if ptr.is_null() {
            return Err(MemlockError::AllocationFailed);
        }

        // SAFETY: ptr is non-null
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        // SAFETY: ptr points to valid memory
        unsafe {
            core::ptr::write(ptr.as_ptr(), value);
        }

        Ok(Self {
            ptr,
            layout,
            locked: false,
            _marker: PhantomData,
        })
    }

    /// Returns `true` if the memory is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns the size of the locked memory in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.layout.size()
    }
}

impl<T: Zeroize> Deref for LockedBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: ptr is always valid while LockedBox exists
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Zeroize> DerefMut for LockedBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: ptr is always valid while LockedBox exists
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: Zeroize> AsRef<T> for LockedBox<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T: Zeroize> AsMut<T> for LockedBox<T> {
    fn as_mut(&mut self) -> &mut T {
        self
    }
}

impl<T: Zeroize> Drop for LockedBox<T> {
    fn drop(&mut self) {
        // SAFETY: ptr is valid until this point
        unsafe {
            // Step 1: Zeroize the contents
            (*self.ptr.as_ptr()).zeroize();

            // Step 2: Unlock if locked (ignore errors during drop)
            if self.locked {
                let _ = unlock_memory(self.ptr.as_ptr() as *const u8, self.layout.size());
            }

            // Step 3: Deallocate
            dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

// Implement ZeroizeOnDrop marker for documentation purposes
// (actual zeroisation happens in Drop)
impl<T: Zeroize> ZeroizeOnDrop for LockedBox<T> {}

// SAFETY: LockedBox owns its data exclusively (like Box)
unsafe impl<T: Zeroize + Send> Send for LockedBox<T> {}
unsafe impl<T: Zeroize + Sync> Sync for LockedBox<T> {}

impl<T: Zeroize + fmt::Debug> fmt::Debug for LockedBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't expose the contents - just metadata
        f.debug_struct("LockedBox")
            .field("size", &self.layout.size())
            .field("locked", &self.locked)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// LockedVec<T> - Variable-length locked buffer
// ============================================================================

/// A variable-length buffer with memory locked into RAM.
///
/// Similar to `Vec<u8>` but with memory locking and automatic zeroisation.
pub struct LockedVec {
    ptr: NonNull<u8>,
    len: usize,
    capacity: usize,
    layout: Layout,
    locked: bool,
}

impl LockedVec {
    /// Creates a new `LockedVec` with the specified capacity.
    ///
    /// The memory is allocated and locked immediately, but the length is 0.
    pub fn with_capacity(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(MemlockError::InvalidSize);
        }

        let layout = Layout::array::<u8>(capacity).map_err(|_| MemlockError::InvalidSize)?;

        // SAFETY: Layout is valid and non-zero
        let ptr = unsafe { alloc(layout) };

        if ptr.is_null() {
            return Err(MemlockError::AllocationFailed);
        }

        // SAFETY: ptr is non-null
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        // Lock the memory
        let lock_result = lock_memory(ptr.as_ptr(), capacity);
        let _ = advise_secret(ptr.as_ptr(), capacity);

        match lock_result {
            Ok(()) => Ok(Self {
                ptr,
                len: 0,
                capacity,
                layout,
                locked: true,
            }),
            Err(e) => {
                // SAFETY: ptr is valid
                unsafe {
                    dealloc(ptr.as_ptr(), layout);
                }
                Err(e)
            }
        }
    }

    /// Creates a `LockedVec` from existing bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut vec = Self::with_capacity(data.len())?;
        vec.extend_from_slice(data);
        Ok(vec)
    }

    /// Appends bytes to the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length would exceed capacity.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        assert!(
            self.len + data.len() <= self.capacity,
            "LockedVec capacity exceeded"
        );

        // SAFETY: We've verified there's enough capacity
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.ptr.as_ptr().add(self.len),
                data.len(),
            );
        }
        self.len += data.len();
    }

    /// Returns the current length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns `true` if locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns a slice of the contents.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for len bytes
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Returns a mutable slice of the contents.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for len bytes
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedVec {
    fn drop(&mut self) {
        // SAFETY: ptr is valid
        unsafe {
            // Zeroize entire capacity (not just len)
            core::ptr::write_bytes(self.ptr.as_ptr(), 0, self.capacity);

            if self.locked {
                let _ = unlock_memory(self.ptr.as_ptr(), self.capacity);
            }

            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

impl Zeroize for LockedVec {
    fn zeroize(&mut self) {
        // SAFETY: ptr is valid for capacity bytes
        unsafe {
            core::ptr::write_bytes(self.ptr.as_ptr(), 0, self.capacity);
        }
        self.len = 0;
    }
}

impl AsRef<[u8]> for LockedVec {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for LockedVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedVec")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("locked", &self.locked)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

// SAFETY: LockedVec owns its data exclusively
unsafe impl Send for LockedVec {}
unsafe impl Sync for LockedVec {}

// ============================================================================
// GuardedBox<T> - Smart pointer with guard pages
// ============================================================================

/// A heap-allocated value with guard pages for overflow detection.
///
/// `GuardedBox<T>` provides the highest level of memory protection:
///
/// 1. **Guard pages**: Inaccessible memory pages before and after the data
///    that will cause an immediate crash if accessed, detecting buffer
///    overflows and underflows.
///
/// 2. **Memory locking**: The data is locked into RAM (if privileges allow),
///    preventing it from being swapped to disk.
///
/// 3. **Page-aligned allocation**: Uses `posix_memalign`/`VirtualAlloc` for
///    proper alignment required by guard pages.
///
/// 4. **Automatic zeroisation**: When dropped, the memory is securely zeroed
///    before being deallocated.
///
/// 5. **Optional read-only protection**: After initialisation, the data can
///    be marked read-only to prevent accidental modification.
///
/// # Memory Layout
///
/// ```text
/// ┌─────────────┬───────────────────┬─────────────┐
/// │ Guard Page  │   Data (locked)   │ Guard Page  │
/// │ (PROT_NONE) │   (PROT_READ/RW)  │ (PROT_NONE) │
/// └─────────────┴───────────────────┴─────────────┘
/// ```
///
/// # Example
///
/// ```ignore
/// use trelis_primitives::memlock::GuardedBox;
///
/// // Create a guarded secret key
/// let mut secret_key: GuardedBox<[u8; 32]> = GuardedBox::new([0u8; 32])?;
///
/// // Initialize the key...
/// secret_key.as_mut()[..].copy_from_slice(&key_bytes);
///
/// // Make it read-only (optional)
/// secret_key.protect_readonly()?;
///
/// // Any buffer overflow into the guard pages will crash immediately
/// ```
///
/// # When to Use
///
/// Use `GuardedBox` for:
/// - Long-lived cryptographic keys (identity keys, signing keys)
/// - High-value secrets that justify the memory overhead
///
/// Use `LockedBox` instead when:
/// - Memory overhead is a concern (GuardedBox uses 2 extra pages)
/// - You're storing many small secrets
/// - Guard page protection isn't critical
pub struct GuardedBox<T: Zeroize> {
    /// Pointer to the data (between guard pages)
    data_ptr: NonNull<T>,
    /// Pointer to the full allocation (including guard pages)
    alloc_ptr: NonNull<u8>,
    /// Total allocation size (data pages + 2 guard pages)
    alloc_size: usize,
    /// Size of the data region (page-aligned)
    data_size: usize,
    /// Whether the memory is locked
    locked: bool,
    /// Whether the data is read-only
    readonly: bool,
    _marker: PhantomData<T>,
}

impl<T: Zeroize> GuardedBox<T> {
    /// Creates a new `GuardedBox` containing the given value.
    ///
    /// The memory layout is:
    /// - One guard page (inaccessible)
    /// - Data pages (locked and read-write)
    /// - One guard page (inaccessible)
    ///
    /// # Errors
    ///
    /// Returns `MemlockError::AllocationFailed` if allocation fails.
    /// Returns `MemlockError::ProtectFailed` if guard page protection fails.
    /// Returns `MemlockError::LockFailed` if `mlock(2)` fails — symmetric with
    /// [`LockedBox::new`]. The value is zeroised and the
    /// allocation freed before the error is returned, so no partially-
    /// initialised `GuardedBox` is ever returned. Callers who want guard
    /// pages without mlock should use [`new_unlocked`](Self::new_unlocked).
    pub fn new(value: T) -> Result<Self> {
        Self::new_with_lock(value, true)
    }

    /// Creates a `GuardedBox` without memory locking.
    ///
    /// Guard pages and zeroize-on-drop are still applied; only the
    /// `mlock(2)` step is skipped. Useful when the caller has explicitly
    /// decided not to rely on mlock (e.g., on a platform where it always
    /// fails) but still wants the rest of the protection.
    ///
    /// # Security Note
    ///
    /// Without memory locking the data may be swapped to disc. Use this
    /// only when `new()` is known to fail (e.g., a `RLIMIT_MEMLOCK`-
    /// constrained host) or when locking is genuinely not desired.
    pub fn new_unlocked(value: T) -> Result<Self> {
        Self::new_with_lock(value, false)
    }

    /// Shared constructor for [`new`](Self::new) and [`new_unlocked`](Self::new_unlocked).
    fn new_with_lock(value: T, lock: bool) -> Result<Self> {
        let ps = page_size();
        let data_size = page_round(core::mem::size_of::<T>(), ps);

        if data_size == 0 {
            return Err(MemlockError::InvalidSize);
        }

        // Total allocation: guard page + data + guard page
        let alloc_size = ps + data_size + ps;

        // Allocate page-aligned memory
        let (alloc_ptr, _) = page_aligned_alloc(alloc_size)?;

        // SAFETY: alloc_ptr is valid and non-null
        let alloc_ptr = unsafe { NonNull::new_unchecked(alloc_ptr) };

        // Calculate pointers to each region
        let fore_guard = alloc_ptr.as_ptr();
        let data_ptr = unsafe { alloc_ptr.as_ptr().add(ps) };
        let aft_guard = unsafe { alloc_ptr.as_ptr().add(ps + data_size) };

        // Set up guard pages (PROT_NONE)
        if protect_noaccess(fore_guard, ps).is_err() {
            // Clean up on failure
            unsafe { page_aligned_free(alloc_ptr.as_ptr(), alloc_size) };
            return Err(MemlockError::ProtectFailed { os_error: 0 });
        }

        if protect_noaccess(aft_guard, ps).is_err() {
            // Restore fore guard and clean up
            let _ = protect_readwrite(fore_guard, ps);
            unsafe { page_aligned_free(alloc_ptr.as_ptr(), alloc_size) };
            return Err(MemlockError::ProtectFailed { os_error: 0 });
        }

        // Write the value to the data region
        // SAFETY: data_ptr is valid and properly aligned
        unsafe {
            core::ptr::write(data_ptr as *mut T, value);
        }

        // Lock the data region. Symmetric with `LockedBox::new`: failure is
        // fatal. Callers who want guard pages without mlock must call
        // `new_unlocked` explicitly.
        let locked = if lock {
            match lock_memory(data_ptr, data_size) {
                Ok(()) => true,
                Err(e) => {
                    // SAFETY: data_ptr is valid and initialised; restore guard
                    // pages to RW so deallocation succeeds.
                    unsafe {
                        (*(data_ptr as *mut T)).zeroize();
                        let _ = protect_readwrite(fore_guard, ps);
                        let _ = protect_readwrite(aft_guard, ps);
                        page_aligned_free(alloc_ptr.as_ptr(), alloc_size);
                    }
                    return Err(e);
                }
            }
        } else {
            false
        };

        // Advise kernel about secret data (non-fatal)
        let _ = advise_secret(data_ptr, data_size);

        Ok(Self {
            data_ptr: unsafe { NonNull::new_unchecked(data_ptr as *mut T) },
            alloc_ptr,
            alloc_size,
            data_size,
            locked,
            readonly: false,
            _marker: PhantomData,
        })
    }

    /// Makes the data region read-only.
    ///
    /// After calling this, any attempt to write to the data will cause a crash.
    /// Use this after initialising a key to prevent accidental modification.
    ///
    /// # Errors
    ///
    /// Returns `MemlockError::ProtectFailed` if the protection change fails.
    pub fn protect_readonly(&mut self) -> Result<()> {
        if self.readonly {
            return Ok(()); // Already read-only
        }

        protect_readonly(self.data_ptr.as_ptr() as *const u8, self.data_size)?;
        self.readonly = true;
        Ok(())
    }

    /// Restores read-write access to the data region.
    ///
    /// # Errors
    ///
    /// Returns `MemlockError::ProtectFailed` if the protection change fails.
    pub fn protect_readwrite(&mut self) -> Result<()> {
        if !self.readonly {
            return Ok(()); // Already read-write
        }

        protect_readwrite(self.data_ptr.as_ptr() as *mut u8, self.data_size)?;
        self.readonly = false;
        Ok(())
    }

    /// Returns `true` if the memory is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns `true` if the data is read-only.
    #[must_use]
    pub fn is_readonly(&self) -> bool {
        self.readonly
    }

    /// Returns the size of the data in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        core::mem::size_of::<T>()
    }

    /// Returns the total allocated size including guard pages.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.alloc_size
    }
}

impl<T: Zeroize> Deref for GuardedBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: data_ptr is always valid while GuardedBox exists
        unsafe { self.data_ptr.as_ref() }
    }
}

impl<T: Zeroize> DerefMut for GuardedBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // Note: This will crash if the memory is read-only protected
        // SAFETY: data_ptr is always valid while GuardedBox exists
        unsafe { self.data_ptr.as_mut() }
    }
}

impl<T: Zeroize> AsRef<T> for GuardedBox<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T: Zeroize> AsMut<T> for GuardedBox<T> {
    fn as_mut(&mut self) -> &mut T {
        self
    }
}

impl<T: Zeroize> Drop for GuardedBox<T> {
    fn drop(&mut self) {
        let ps = page_size();

        // SAFETY: All pointers are valid until this point
        unsafe {
            // Step 1: Restore read-write access if needed (required for zeroisation)
            if self.readonly {
                let _ = protect_readwrite(self.data_ptr.as_ptr() as *mut u8, self.data_size);
            }

            // Step 2: Zeroize the contents
            (*self.data_ptr.as_ptr()).zeroize();

            // Step 3: Unlock if locked
            if self.locked {
                let _ = unlock_memory(self.data_ptr.as_ptr() as *const u8, self.data_size);
            }

            // Step 4: Restore guard pages to read-write for deallocation
            let fore_guard = self.alloc_ptr.as_ptr();
            let aft_guard = self.alloc_ptr.as_ptr().add(ps + self.data_size);
            let _ = protect_readwrite(fore_guard, ps);
            let _ = protect_readwrite(aft_guard, ps);

            // Step 5: Deallocate
            page_aligned_free(self.alloc_ptr.as_ptr(), self.alloc_size);
        }
    }
}

impl<T: Zeroize> Zeroize for GuardedBox<T> {
    fn zeroize(&mut self) {
        // Restore write access if needed
        if self.readonly {
            let _ = protect_readwrite(self.data_ptr.as_ptr() as *mut u8, self.data_size);
            self.readonly = false;
        }
        // SAFETY: data_ptr is valid
        unsafe {
            (*self.data_ptr.as_ptr()).zeroize();
        }
    }
}

impl<T: Zeroize> ZeroizeOnDrop for GuardedBox<T> {}

// SAFETY: GuardedBox owns its data exclusively
unsafe impl<T: Zeroize + Send> Send for GuardedBox<T> {}
unsafe impl<T: Zeroize + Sync> Sync for GuardedBox<T> {}

impl<T: Zeroize + fmt::Debug> fmt::Debug for GuardedBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedBox")
            .field("size", &self.size())
            .field("total_size", &self.alloc_size)
            .field("locked", &self.locked)
            .field("readonly", &self.readonly)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Returns the maximum amount of memory that can be locked (in bytes).
///
/// On Unix, this queries `RLIMIT_MEMLOCK`. Returns `None` if unlimited or
/// if the limit cannot be determined.
#[cfg(unix)]
pub fn memlock_limit() -> Option<usize> {
    let mut rlim: libc::rlimit = unsafe { core::mem::zeroed() };

    // SAFETY: getrlimit is safe with valid rlimit pointer
    let result = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) };

    if result == 0 {
        if rlim.rlim_cur == libc::RLIM_INFINITY {
            None // Unlimited
        } else {
            Some(rlim.rlim_cur as usize)
        }
    } else {
        None
    }
}

/// Returns the memory locking limit (non-Unix stub).
///
/// Always returns `None` on non-Unix platforms as there's no standard
/// way to query memory locking limits.
#[cfg(not(unix))]
pub fn memlock_limit() -> Option<usize> {
    None
}

/// Checks if memory locking is available on this system.
///
/// This attempts a small test lock to verify privileges.
pub fn is_mlock_available() -> bool {
    let test_page = page_size();
    let layout = match Layout::from_size_align(test_page, test_page) {
        Ok(l) => l,
        Err(_) => return false,
    };

    // SAFETY: Valid layout
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return false;
    }

    let result = lock_memory(ptr, test_page).is_ok();

    if result {
        let _ = unlock_memory(ptr, test_page);
    }

    // SAFETY: ptr was allocated with this layout
    unsafe {
        dealloc(ptr, layout);
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::format;
    use std::println;

    #[test]
    fn test_page_size() {
        let size = page_size();
        assert!(size >= 4096, "Page size should be at least 4KB");
        assert!(size.is_power_of_two(), "Page size should be power of 2");
    }

    #[test]
    fn test_locked_box_unlocked_fallback() {
        // This should always work even without privileges
        let boxed: LockedBox<[u8; 32]> = LockedBox::new_unlocked([42u8; 32]).unwrap();
        assert_eq!(boxed[0], 42);
        assert!(!boxed.is_locked());
        assert_eq!(boxed.size(), 32);
    }

    #[test]
    fn test_locked_box_deref() {
        let boxed: LockedBox<[u8; 4]> = LockedBox::new_unlocked([1, 2, 3, 4]).unwrap();
        assert_eq!(&*boxed, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_locked_box_deref_mut() {
        let mut boxed: LockedBox<[u8; 4]> = LockedBox::new_unlocked([0; 4]).unwrap();
        boxed[0] = 99;
        assert_eq!(boxed[0], 99);
    }

    #[test]
    fn test_locked_box_debug_redacted() {
        let boxed: LockedBox<[u8; 32]> = LockedBox::new_unlocked([0xAA; 32]).unwrap();
        let debug_str = format!("{:?}", boxed);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("170")); // 0xAA = 170
    }

    #[test]
    fn test_locked_vec_basic() {
        let mut vec = LockedVec::with_capacity(64).unwrap_or_else(|_| {
            // Fall back to unlocked if mlock fails
            let layout = Layout::array::<u8>(64).unwrap();
            let ptr = unsafe { alloc(layout) };
            let ptr = unsafe { NonNull::new_unchecked(ptr) };
            LockedVec {
                ptr,
                len: 0,
                capacity: 64,
                layout,
                locked: false,
            }
        });

        assert!(vec.is_empty());
        vec.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(vec.len(), 4);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_mlock_availability() {
        // This test just verifies the function doesn't panic
        let available = is_mlock_available();
        println!("mlock available: {}", available);
    }

    #[test]
    fn test_memlock_limit() {
        if let Some(limit) = memlock_limit() {
            println!("memlock limit: {} bytes ({} KB)", limit, limit / 1024);
        } else {
            println!("memlock limit: unlimited or unknown");
        }
    }

    #[test]
    fn test_zero_size_rejected() {
        // Zero-sized types should be rejected
        let result: Result<LockedBox<()>> = LockedBox::new(());
        assert!(matches!(result, Err(MemlockError::InvalidSize)));
    }

    // Integration test with actual mlock (may fail without privileges)
    #[test]
    fn test_locked_box_with_mlock() {
        match LockedBox::new([0u8; 32]) {
            Ok(boxed) => {
                assert!(boxed.is_locked());
                println!("mlock succeeded - memory is locked");
            }
            Err(MemlockError::LockFailed { os_error }) => {
                println!(
                    "mlock failed (expected without privileges): errno={}",
                    os_error
                );
                // EPERM (1) or ENOMEM (12) are expected without CAP_IPC_LOCK
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // ========================================================================
    // Direct lock_memory/unlock_memory tests
    // ========================================================================

    #[test]
    fn test_lock_unlock_memory_direct() {
        // Allocate page-aligned memory for best compatibility
        let size = page_size();
        let layout = Layout::from_size_align(size, size).unwrap();
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());

        // Try to lock
        match lock_memory(ptr, size) {
            Ok(()) => {
                println!("lock_memory succeeded");
                // Unlock should also succeed
                let unlock_result = unlock_memory(ptr, size);
                assert!(
                    unlock_result.is_ok(),
                    "unlock after successful lock should work"
                );
            }
            Err(MemlockError::LockFailed { os_error }) => {
                // This is expected without privileges
                println!(
                    "lock_memory failed with errno={} (expected without CAP_IPC_LOCK)",
                    os_error
                );
                // Verify errno is a valid positive value (not garbage)
                assert!(os_error > 0, "errno should be positive");
            }
            Err(e) => panic!("Unexpected error type: {:?}", e),
        }

        unsafe { dealloc(ptr, layout) };
    }

    #[test]
    fn test_lock_memory_zero_length() {
        // Zero-length lock should succeed as a no-op
        let result = lock_memory(core::ptr::null(), 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unlock_memory_zero_length() {
        // Zero-length unlock should succeed as a no-op
        let result = unlock_memory(core::ptr::null(), 0);
        assert!(result.is_ok());
    }

    // ========================================================================
    // LockedVec additional tests
    // ========================================================================

    #[test]
    fn test_locked_vec_from_slice() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        match LockedVec::from_slice(&data) {
            Ok(vec) => {
                assert_eq!(vec.len(), 8);
                assert_eq!(vec.as_slice(), &data);
                println!(
                    "LockedVec::from_slice succeeded, locked={}",
                    vec.is_locked()
                );
            }
            Err(MemlockError::LockFailed { os_error }) => {
                println!("LockedVec::from_slice mlock failed: errno={}", os_error);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_locked_vec_zeroize() {
        let layout = Layout::array::<u8>(32).unwrap();
        let ptr = unsafe { alloc(layout) };
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        let mut vec = LockedVec {
            ptr,
            len: 0,
            capacity: 32,
            layout,
            locked: false,
        };

        vec.extend_from_slice(&[0xAA; 16]);
        assert_eq!(vec.len(), 16);
        assert_eq!(vec.as_slice()[0], 0xAA);

        // Zeroize should clear and reset length
        vec.zeroize();
        assert_eq!(vec.len(), 0);

        // Verify underlying memory is zeroed (check capacity, not len)
        let raw_slice = unsafe { core::slice::from_raw_parts(vec.ptr.as_ptr(), vec.capacity()) };
        assert!(raw_slice.iter().all(|&b| b == 0), "memory should be zeroed");
    }

    #[test]
    fn test_locked_vec_zero_capacity_rejected() {
        let result = LockedVec::with_capacity(0);
        assert!(matches!(result, Err(MemlockError::InvalidSize)));
    }

    #[test]
    fn test_locked_vec_debug_redacted() {
        let layout = Layout::array::<u8>(16).unwrap();
        let ptr = unsafe { alloc(layout) };
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        let mut vec = LockedVec {
            ptr,
            len: 0,
            capacity: 16,
            layout,
            locked: false,
        };
        vec.extend_from_slice(&[0xBB; 8]);

        let debug_str = format!("{:?}", vec);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("187")); // 0xBB = 187
    }

    // ========================================================================
    // Error display tests
    // ========================================================================

    #[test]
    fn test_memlock_error_display() {
        let err = MemlockError::LockFailed { os_error: 12 };
        let msg = format!("{}", err);
        assert!(msg.contains("12"));
        assert!(msg.contains("lock failed"));

        let err = MemlockError::UnlockFailed { os_error: 22 };
        let msg = format!("{}", err);
        assert!(msg.contains("22"));
        assert!(msg.contains("unlock failed"));

        let err = MemlockError::AllocationFailed;
        let msg = format!("{}", err);
        assert!(msg.contains("allocation"));

        let err = MemlockError::InvalidSize;
        let msg = format!("{}", err);
        assert!(msg.contains("invalid size"));

        let err = MemlockError::NotSupported;
        let msg = format!("{}", err);
        assert!(msg.contains("not supported"));
    }

    // ========================================================================
    // advise_secret tests
    // ========================================================================

    #[test]
    fn test_advise_secret_zero_length() {
        // Zero-length should succeed as no-op
        let result = advise_secret(core::ptr::null(), 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_advise_secret_valid_memory() {
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());

        // advise_secret should not fail (may be no-op on non-Linux)
        let result = advise_secret(ptr, 4096);
        assert!(result.is_ok());

        unsafe { dealloc(ptr, layout) };
    }

    // ========================================================================
    // mprotect tests
    // ========================================================================

    #[test]
    fn test_protect_zero_length() {
        // Zero-length protect operations should succeed as no-ops
        assert!(protect_readonly(core::ptr::null(), 0).is_ok());
        assert!(protect_readwrite(core::ptr::null_mut(), 0).is_ok());
        assert!(protect_noaccess(core::ptr::null(), 0).is_ok());
    }

    #[test]
    fn test_protect_roundtrip() {
        // Allocate page-aligned memory
        let (ptr, size) = match page_aligned_alloc(4096) {
            Ok(result) => result,
            Err(_) => {
                println!("page_aligned_alloc failed, skipping test");
                return;
            }
        };

        // Write some data
        unsafe {
            core::ptr::write_bytes(ptr, 0xAA, size);
        }

        // Test readonly -> readwrite roundtrip
        match protect_readonly(ptr, size) {
            Ok(()) => {
                println!("protect_readonly succeeded");
                // Should be able to read
                let val = unsafe { *ptr };
                assert_eq!(val, 0xAA);

                // Restore read-write
                assert!(protect_readwrite(ptr, size).is_ok());

                // Should be able to write again
                unsafe { *ptr = 0xBB };
                assert_eq!(unsafe { *ptr }, 0xBB);
            }
            Err(MemlockError::ProtectFailed { os_error }) => {
                println!(
                    "protect_readonly failed: errno={} (may need privileges)",
                    os_error
                );
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        unsafe { page_aligned_free(ptr, size) };
    }

    #[test]
    fn test_page_round() {
        assert_eq!(page_round(1, 4096), 4096);
        assert_eq!(page_round(4096, 4096), 4096);
        assert_eq!(page_round(4097, 4096), 8192);
        assert_eq!(page_round(0, 4096), 0);
    }

    #[test]
    fn test_page_aligned_alloc_basic() {
        match page_aligned_alloc(4096) {
            Ok((ptr, size)) => {
                assert!(!ptr.is_null());
                assert!(size >= 4096);
                // Check alignment
                assert_eq!(ptr as usize % page_size(), 0);
                unsafe { page_aligned_free(ptr, size) };
            }
            Err(e) => panic!("page_aligned_alloc failed: {:?}", e),
        }
    }

    // ========================================================================
    // GuardedBox tests
    // ========================================================================

    #[test]
    fn test_guarded_box_basic() {
        match GuardedBox::new([42u8; 32]) {
            Ok(boxed) => {
                assert_eq!(boxed[0], 42);
                assert_eq!(boxed.size(), 32);
                // Total size should include 2 guard pages
                assert!(boxed.total_size() >= boxed.size() + 2 * page_size());
                println!(
                    "GuardedBox created: size={}, total={}, locked={}",
                    boxed.size(),
                    boxed.total_size(),
                    boxed.is_locked()
                );
            }
            Err(MemlockError::ProtectFailed { os_error }) => {
                println!("GuardedBox::new failed (mprotect): errno={}", os_error);
            }
            Err(MemlockError::LockFailed { os_error }) => {
                // GuardedBox::new now fails on mlock failure; expected without
                // CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK.
                println!("GuardedBox::new failed (mlock): errno={}", os_error);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_guarded_box_deref() {
        match GuardedBox::new([1u8, 2, 3, 4]) {
            Ok(boxed) => {
                assert_eq!(&*boxed, &[1, 2, 3, 4]);
            }
            Err(_) => println!("GuardedBox::new failed, skipping test"),
        }
    }

    #[test]
    fn test_guarded_box_deref_mut() {
        match GuardedBox::new([0u8; 4]) {
            Ok(mut boxed) => {
                boxed[0] = 99;
                assert_eq!(boxed[0], 99);
            }
            Err(_) => println!("GuardedBox::new failed, skipping test"),
        }
    }

    #[test]
    fn test_guarded_box_readonly() {
        match GuardedBox::new([42u8; 32]) {
            Ok(mut boxed) => {
                // Make read-only
                match boxed.protect_readonly() {
                    Ok(()) => {
                        assert!(boxed.is_readonly());
                        // Can still read
                        assert_eq!(boxed[0], 42);

                        // Restore read-write
                        assert!(boxed.protect_readwrite().is_ok());
                        assert!(!boxed.is_readonly());

                        // Can write again
                        boxed[0] = 99;
                        assert_eq!(boxed[0], 99);
                    }
                    Err(_) => println!("protect_readonly failed, skipping"),
                }
            }
            Err(_) => println!("GuardedBox::new failed, skipping test"),
        }
    }

    #[test]
    fn test_guarded_box_debug_redacted() {
        match GuardedBox::new([0xAAu8; 32]) {
            Ok(boxed) => {
                let debug_str = format!("{:?}", boxed);
                assert!(debug_str.contains("REDACTED"));
                assert!(debug_str.contains("GuardedBox"));
                assert!(!debug_str.contains("170")); // 0xAA = 170
            }
            Err(_) => println!("GuardedBox::new failed, skipping test"),
        }
    }

    #[test]
    fn test_guarded_box_zeroize() {
        match GuardedBox::new([0xFFu8; 32]) {
            Ok(mut boxed) => {
                assert_eq!(boxed[0], 0xFF);

                // Zeroize
                boxed.zeroize();
                assert_eq!(boxed[0], 0);
            }
            Err(_) => println!("GuardedBox::new failed, skipping test"),
        }
    }

    #[test]
    fn test_guarded_box_zero_size_rejected() {
        let result: Result<GuardedBox<()>> = GuardedBox::new(());
        assert!(matches!(result, Err(MemlockError::InvalidSize)));
    }

    #[test]
    fn test_protect_failed_error_display() {
        let err = MemlockError::ProtectFailed { os_error: 13 };
        let msg = format!("{}", err);
        assert!(msg.contains("13"));
        assert!(msg.contains("protection"));
    }
}
