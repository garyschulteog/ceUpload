#Cost Element Lookup Table Uploader

Using google sheets api


## Instructions for running
* get your google sheets api creds: 
  * https://developers.google.com/sheets/api/quickstart/go
  * download the credentials as a `credentials.json` from the dialog
* talk to a workforce team member to get oidc creds for uploading the cost element
  * save the creds as `keycloakCreds.json`
* run the pre-built binary, follow the link, approve read access, paste the token into the console


## Instructions for building
* setup your go environment.  google it, it is pretty easy
* get the sheets and oauth2 api libs
  * `go get -u google.golang.org/api/sheets/v4`
  * `go get -u golang.org/x/oauth2/google`
  * `go get github.com/xeipuuv/gojsonschema`


## Regenerating struct types from json schema:
* `go get github.com/atombender/go-jsonschema`
* `gojsonschema -p main cost-element.json > ceType.go`



## Todo:
* bazel-ize this
* upload an osx go binary for easier use
* create a credentials options to support both prod and integ
* symmetric encrypt creds and check in to help with the cs-workflow (only one secret to deal with)