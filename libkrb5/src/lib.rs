mod ccache;
pub use ccache::Krb5CCache;

mod cccol;
pub use cccol::Krb5CCCol;

mod context;
pub use context::{Krb5AuthContext, Krb5Context};

mod credential;
pub use credential::{Krb5Creds, Krb5Keyblock, Krb5Keytab};

mod error;
pub use error::Krb5Error;

mod principal;
pub use principal::{Krb5Principal, Krb5PrincipalData};

mod strconv;

#[allow(dead_code)]
static C_FALSE: u32 = 0;
#[allow(dead_code)]
static C_TRUE: u32 = 1;

#[cfg(test)]
mod tests;
