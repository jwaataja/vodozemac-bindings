use super::{ffi::SessionKeys, Curve25519PublicKey, OlmMessage};

pub struct Session(pub(crate) vodozemac::olm::Session);

impl Session {
    pub fn session_id(&self) -> String {
        self.0.session_id()
    }

    pub fn pickle(&self, pickle_key: &[u8; 32]) -> String {
        self.0.pickle().encrypt(pickle_key)
    }

    pub fn encrypt(&mut self, plaintext: &str) -> Box<OlmMessage> {
        OlmMessage(self.0.encrypt(plaintext)).into()
    }

    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String, anyhow::Error> {
        Ok(self.0.decrypt(&message.0)?)
    }

    pub fn session_keys(&self) -> SessionKeys {
        let session_keys = self.0.session_keys();

        SessionKeys {
            identity_key: Curve25519PublicKey(session_keys.identity_key).into(),
            base_key: Curve25519PublicKey(session_keys.base_key).into(),
            one_time_key: Curve25519PublicKey(session_keys.one_time_key).into(),
        }
    }

    pub fn session_matches(&self, message: &OlmMessage) -> bool {
        if let vodozemac::olm::OlmMessage::PreKey(m) = &message.0 {
            self.0.session_keys() == m.session_keys()
        } else {
            false
        }
    }

    pub fn session_matches_from(
        &self,
        their_identitiy_key: &Curve25519PublicKey,
        message: &OlmMessage,
    ) -> bool {
        if let vodozemac::olm::OlmMessage::PreKey(m) = &message.0 {
            self.0.session_keys() == m.session_keys()
                && self.0.session_keys().identity_key == their_identitiy_key.0
        } else {
            false
        }
    }

    pub fn has_received_message(&self) -> bool {
        self.0.has_received_message()
    }
}

pub fn session_from_pickle(
    pickle: &str,
    pickle_key: &[u8; 32],
) -> Result<Box<Session>, anyhow::Error> {
    let pickle = vodozemac::olm::SessionPickle::from_encrypted(pickle, pickle_key)?;
    Ok(Session(vodozemac::olm::Session::from_pickle(pickle)).into())
}

pub fn session_from_libolm_pickle(
    pickle: &str,
    pickle_key: &str,
) -> Result<Box<Session>, anyhow::Error> {
    Ok(Session(vodozemac::olm::Session::from_libolm_pickle(
        pickle, pickle_key,
    )?)
    .into())
}
