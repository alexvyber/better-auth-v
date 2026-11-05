module main

import better_auth

struct Command {
	id                   int
	op                   string
	now_millis           i64
	now                  i64
	options              Options
	jwt_options_json     string
	jwt_expiration_json  string
	jwt_callback_prefix  string
	jwt_callback_methods []string
	prepared_json        string
	hook_request         ?better_auth.Request
	hook_response        ?better_auth.Response
	request              better_auth.Request
	transactions         bool = true
	direct               bool
	where_json           string = '[]'
	model                string
	password             string
	hash                 string
	method               string
	arguments_json       string = '[]'
}

struct Reply {
	id                 int
	error              ?string
	error_status       int
	error_is_api       bool
	error_code         string
	error_mongo        bool
	error_mongo_code   int
	error_mongo_labels []string
	response           ?better_auth.Response
	emails             []better_auth.EmailMessage @[skip]
	logs               []better_auth.LogEvent
	records_json       string = '[]'
	value_json         string = 'null'
}

struct State {
mut:
	now_millis    i64
	now           i64
	emails        []better_auth.EmailMessage
	fail_delivery bool
	logs          []better_auth.LogEvent
}
