module better_auth

struct RateBucket {
	window_millis i64
	start         i64
	count         int
}
