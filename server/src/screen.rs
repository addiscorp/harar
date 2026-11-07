//! Whether this login session's screen is locked (macOS).

/// `Some(true)` while the screen is locked, `None` where it can't be told
/// (no window server session, or not macOS).
pub fn is_locked() -> Option<bool> {
    imp::is_locked()
}

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::dictionary::CFDictionaryRef;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    pub fn is_locked() -> Option<bool> {
        // SAFETY: returns an owned dictionary or null; no arguments.
        let dict = unsafe { CGSessionCopyCurrentDictionary() };
        if dict.is_null() {
            return None;
        }
        // SAFETY: non-null result follows the Create rule.
        let dict: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(dict) };
        let key = CFString::new("CGSSessionScreenIsLocked");
        // The key is absent while the screen is unlocked.
        let Some(value) = dict.find(key.as_CFTypeRef()) else {
            return Some(false);
        };
        // SAFETY: dictionary values are CF objects it retains.
        let value = unsafe { CFType::wrap_under_get_rule(*value) };
        Some(value.downcast::<CFBoolean>().is_some_and(bool::from))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn is_locked() -> Option<bool> {
        None
    }
}
