module better_auth

// Bearer is opt-in because cookie and bearer credentials have different exposure
// and browser security properties.
pub struct BearerPlugin {}

pub fn (_ BearerPlugin) id() string {
	return 'bearer'
}

pub fn (_ BearerPlugin) endpoints() []Endpoint {
	return []Endpoint{}
}
