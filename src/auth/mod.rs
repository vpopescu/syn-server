pub (crate) trait Auth {
    fn authenticate(&self, realm: Option<String>, username: &str, password: &str) -> bool;
}

#[derive(Clone)]
pub (crate) struct SimpleAuth {
    realm: Option<String>,
    username: String,
    password: String,
}

impl SimpleAuth {
    pub fn new() -> Self {
        Self {
            realm: None,
            username: "user".to_string(),
            password: "demo".to_string(),
        }
    }
}

impl Auth for SimpleAuth {
    fn authenticate(&self, realm: Option<String>, username: &str, password: &str) -> bool {

        if self.realm != realm {
            return false;
        }
        if self.username != username {
            return false;
        }
        if self.password != password {
            return false;
        }
        true
    }

}

