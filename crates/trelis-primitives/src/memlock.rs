//! Memory locking to prevent secrets from being swapped to disk.
//!
//! This module provides OS-level memory protection for sensitive cryptographic
//! material. When enabled, secrets are locked into physical RAM and cannot be
//! swapped to disk, protecting against cold boot attacks and swap file forensics.
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
//! # Usage
//!
//! ```ignore
//! use trelis_primitives::memlock::{LockedBox, lock_memory, MemlockError};
//!
//! // Option 1: Use LockedBox for automatic lock/unlock lifecycle
//! let secret_key = LockedBox::new([0u8; 32])?;
//! // Memory is locked, use secret_key.as_ref() to access
//! // Automatically unlocked and zeroized on drop
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
// LockedBox<T> - Smart pointer with automatic memory locking
// ============================================================================

/// A heap-allocated value with memory locked into RAM.
///
/// `LockedBox<T>` is similar to `Box<T>` but with additional security guarantees:
///
/// 1. **Memory locking**: The underlying memory is locked into RAM using `mlock(2)`,
///    preventing it from being swapped to disk.
///
/// 2. **Automatic zeroization**: When dropped, the memory is securely zeroed before
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
/// and the value is securely zeroized before returning. No partially-initialized
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
    /// In case of lock failure, the value is zeroized and deallocated.
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
        // SAFETY: ptr points to valid, uninitialized memory of correct size
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
                // SAFETY: ptr is valid and initialized
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
    /// but you still want the zeroization-on-drop guarantee.
    ///
    /// # Security Note
    ///
    /// Without memory locking, the secret may be swapped to disk. Use this
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
// (actual zeroization happens in Drop)
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
/// Similar to `Vec<u8>` but with memory locking and automatic zeroization.
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
}
