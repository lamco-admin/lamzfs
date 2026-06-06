// SPDX-License-Identifier: MIT
// Adapted from rzfs @ea41cf0b5b29 (dual GPL-2.0 OR MIT; MIT elected); see NOTICE.
use core::fmt;

/// String of a fixed capacity, and variable length.
#[derive(Debug)]
pub struct Fstr<const N: usize> {
    bytes: [u8; N],
    size: usize,
    trimmed: bool,
}

impl<const N: usize> fmt::Display for Fstr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // If the bytes are not a valid utf8 sequence, then print them as
        // a byte array.
        match self.as_str() {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "{:?}", &self.bytes[0..self.size]),
        }
    }
}

impl<const N: usize> Fstr<N> {
    /// Creates a new fixed size string. Caller must clamp length.
    fn new(bytes: &[u8], trimmed: bool) -> Fstr<N> {
        let size = bytes.len();

        let mut f = Fstr {
            bytes: [0; N],
            size,
            trimmed,
        };

        f.bytes[0..size].copy_from_slice(bytes);

        f
    }

    /// Gets string bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[0..self.size]
    }

    /** Gets bytes decoded as a utf8 string.
     *
     * Returns [None] if byte string failed to decode as utf8.
     */
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }

    /// Gets the capacity of the string in bytes.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Returns [true] if the string is empty [""].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns [true] if the fixed string was trimmed in [`Fstr<N>::from`].
    pub fn is_trimmed(&self) -> bool {
        self.trimmed
    }

    /// Gets the length of the string in bytes.
    pub fn len(&self) -> usize {
        self.size
    }
}

impl<const N: usize> From<&[u8]> for Fstr<N> {
    fn from(bytes: &[u8]) -> Self {
        // Trim input to at most N bytes.
        let size = bytes.len().min(N);
        let trimmed = size < bytes.len();

        Fstr::<N>::new(&bytes[0..size], trimmed)
    }
}

impl<const N: usize> From<&str> for Fstr<N> {
    /** Gets the [`Fstr::<N>`] from the string.
     *
     * If the byte length of `s` is larger than `N`, then the string bytes will
     * try to be trimmed to a valid utf8 string.
     */
    fn from(s: &str) -> Self {
        // Get bytes and length.
        let bytes = s.as_bytes();
        let mut size = bytes.len().min(N);

        if N > 0 && bytes.len() > N {
            // A utf8 string can use up to 4 bytes per code point, so try to
            // find a valid encoding by trimming up to 3 bytes, but leaving
            // at least one byte.
            for truncate in 0..size.min(4) {
                let tsize = size - truncate;
                if core::str::from_utf8(&bytes[0..tsize]).is_ok() {
                    size = tsize;
                    break;
                }
            }
            // Otherwise...just use the bytes as they are.
        }

        let trimmed = size < bytes.len();

        Fstr::<N>::new(&bytes[0..size], trimmed)
    }
}

////////////////////////////////////////////////////////////////////////////////

