pub mod copland;

/// Debug print function that only outputs to stderr in debug builds.
/// In release builds, this function does nothing.
///
/// # Arguments
/// * `message` - The message to print to stderr
///
/// # Example
/// ```
/// use rust_am_lib::debug_print;
/// debug_print("This will only print in debug builds");
/// ```
#[cfg(debug_assertions)]
pub fn debug_print(message: &str) {
    eprintln!("[DEBUG] {}", message);
}

#[cfg(not(debug_assertions))]
pub fn debug_print(_message: &str) {
    // No-op in release builds
}

/// Macro version of DEBUG_PRINT for formatting support
///
/// # Example
/// ```
/// use rust_am_lib::debug_print;
/// debug_print!("Debug value: {}", 42);
/// ```
#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!("[DEBUG] {}", format!($($arg)*));
    };
}
