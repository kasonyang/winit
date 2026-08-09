//! Helpers to mimic password-field input behavior (like `NSSecureTextField`
//! or a browser's `<input type="password">`), mirroring WebKit's
//! `enableSecureTextInput()`:
//!
//! 1. Secure event input, which stops keyboard events from being delivered to
//!    other processes.
//! 2. Restricting the input sources available to this application to the
//!    ASCII-capable ones (`kTSMDocumentEnabledInputSourcesPropertyTag`), so the
//!    input source can no longer be switched while the password field is
//!    focused, and selecting the ASCII source (usually ABC).
//!
//! The previously active input source is remembered and restored on exit.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, CFTypeRef, TCFType};

use super::ffi;

/// Whether this process has enabled secure event input itself.
///
/// `EnableSecureEventInput`/`DisableSecureEventInput` are reference counted;
/// this tracks our own state so the two calls are always paired.
static SECURE_INPUT_ENABLED: AtomicBool = AtomicBool::new(false);

/// The input source that was active before we coerced the keyboard to ASCII,
/// kept alive (owned) so it can be restored when the password field loses
/// focus. `None` when not currently mimicking a password field.
struct PreviousInputSource(Option<*mut ffi::TISInputSource>);

// SAFETY: This pointer is only ever accessed on the main thread (all callers
// run there), always while holding the `Mutex` below.
unsafe impl Send for PreviousInputSource {}
unsafe impl Sync for PreviousInputSource {}

static PREVIOUS_INPUT_SOURCE: Mutex<PreviousInputSource> =
    Mutex::new(PreviousInputSource(None));

/// Enable or disable secure event input for this process.
///
/// While enabled, the system will not deliver keyboard events to other
/// processes.
pub fn set_secure_event_input(enabled: bool) {
    if enabled == SECURE_INPUT_ENABLED.swap(enabled, Ordering::SeqCst) {
        return;
    }
    if enabled {
        // SAFETY: `EnableSecureEventInput` takes no arguments.
        unsafe { ffi::EnableSecureEventInput() };
    } else {
        // SAFETY: `DisableSecureEventInput` takes no arguments.
        unsafe { ffi::DisableSecureEventInput() };
    }
}

/// Remember the currently selected input source, then restrict the available
/// input sources to the ASCII-capable ones and select the first of them.
/// Mirrors what browsers do when a password field is focused.
///
/// This must be paired with [`leave_password_mode`], which restores the input
/// source saved here.
pub fn enter_password_mode() {
    // `TISCopyCurrentKeyboardInputSource` returns a +1 retained reference.
    let current = unsafe { ffi::TISCopyCurrentKeyboardInputSource() };
    if current.is_null() {
        return;
    }

    let mut guard = PREVIOUS_INPUT_SOURCE.lock().unwrap();
    if guard.0.is_none() {
        // First time entering: keep the previous source around for restoration.
        guard.0 = Some(current);
    } else {
        // Already in password mode; drop the redundant reference.
        release_input_source(current);
    }
    drop(guard);

    restrict_to_ascii_input_sources();
}

/// Remove the input source restriction and restore the source that was active
/// before [`enter_password_mode`], releasing the saved reference.
pub fn leave_password_mode() {
    unrestrict_input_sources();

    let mut guard = PREVIOUS_INPUT_SOURCE.lock().unwrap();
    if let Some(previous) = guard.0.take() {
        // SAFETY: `TISSelectInputSource` only reads the input source reference.
        unsafe { ffi::TISSelectInputSource(previous) };
        release_input_source(previous);
    }
}

/// Restrict the input sources selectable by this application to the
/// ASCII-capable ones, then select the first of them (usually "ABC").
fn restrict_to_ascii_input_sources() {
    let sources = unsafe { ffi::TISCreateASCIICapableInputSourceList() };
    if sources.is_null() {
        return;
    }

    // Setting this property on the application's global document (0) restricts
    // the set of input sources the user can switch to while it is in place.
    // `TSMSetDocumentProperty` copies the `CFArrayRef` value from `&sources`
    // synchronously.
    // SAFETY: `sources` is a valid +1 `CFArrayRef` and its address remains
    // valid for the duration of the call.
    unsafe {
        ffi::TSMSetDocumentProperty(
            std::ptr::null_mut(),
            ffi::kTSMDocumentEnabledInputSourcesPropertyTag,
            std::mem::size_of::<*const std::ffi::c_void>() as u32,
            std::ptr::addr_of!(sources) as *mut std::ffi::c_void,
        )
    };

    // SAFETY: `TISCreateASCIICapableInputSourceList` returns a +1 retained
    // `CFArrayRef`; taking ownership under the "create" rule releases it on drop.
    let sources = unsafe { CFArray::<CFType>::wrap_under_create_rule(sources) };

    // `TISSelectInputSource` only reads the input source reference.
    if let Some(source) = sources.iter().next() {
        unsafe { ffi::TISSelectInputSource(source.as_concrete_TypeRef().cast_mut().cast()) };
    }
}

/// Remove the input source restriction set by
/// [`restrict_to_ascii_input_sources`].
fn unrestrict_input_sources() {
    // SAFETY: `TSMRemoveDocumentProperty` only reads the given tag.
    unsafe {
        ffi::TSMRemoveDocumentProperty(
            std::ptr::null_mut(),
            ffi::kTSMDocumentEnabledInputSourcesPropertyTag,
        )
    };
}

/// Release a +1 owned `TISInputSourceRef`.
fn release_input_source(source: *mut ffi::TISInputSource) {
    // SAFETY: `source` is a CF object with a +1 retain count owned by us, so
    // releasing it is balanced.
    unsafe { core_foundation::base::CFRelease(source as CFTypeRef) };
}
