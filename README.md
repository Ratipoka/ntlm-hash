This crate inplements the ntlm hash in pure rust.

# Usage :

```rust
use ntlm_hash::*
println!("{}", ntlm_hash("some_string"))
```
# Limitation :
This crate hashes only strings of maximum 31 characters long.