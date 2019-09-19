package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/sheets/v4"
)

type parseError struct {
	prob string
}

type keycloakCreds struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	User         string `json:"user"`
	Password     string `json:"password"`
}

type CostElementResult struct {
	sheetName   string
	env         string
	workforceId string
	costElement CostElement
	errors      []error
}

type CostElementResponse struct {
	body string
	err  error
}

func (e *parseError) Error() string {
	return fmt.Sprintf(e.prob)
}

var targetEnv string
var keycloak string = "https://auth.%s.opengov.zone/auth/realms/opengov/protocol/openid-connect/token"
var ceEndpoint string = "%s/api/wf_dataset_service/v1/cost_elements"
var schemaLoader = gojsonschema.NewReferenceLoader("file://./cost-element.json")

// Retrieve a token, saves the token, then returns the generated client.
func getClient() *http.Client {
	// get google api creds from file
	b, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, "https://www.googleapis.com/auth/spreadsheets.readonly")
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

func getKeycloakToken(creds keycloakCreds) (oauth2.Token, error) {
	var err error
	tokenResp := oauth2.Token{}
	//hacky.
	cli := http.Client{
		Timeout: time.Second * 2, // Maximum of 2 secs
	}
	body := []byte(fmt.Sprintf("grant_type=password&username=%s&password=%s", creds.User, creds.Password))
	req, err := http.NewRequest(http.MethodPost, keycloak, bytes.NewBuffer(body))
	if err == nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s",
			base64.RawStdEncoding.EncodeToString([]byte(
				fmt.Sprintf("%s:%s", creds.ClientId, creds.ClientSecret)))))
		resp, reqerr := cli.Do(req)
		if resp.StatusCode > 200 {
			err = error(&parseError{"Failed to authorize: " + resp.Status})
		} else {
			err = reqerr
		}
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		}
	}
	return tokenResp, err
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scanln(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func buildLookupTable(sheetName string, rows []*sheets.RowData) TableSource {
	l := TableSourceLookupTablesElem{}
	// get the index of the last non-empty column header
	var rowLastIdx = 0
	for i, col := range rows[16].Values {
		if col.FormattedValue == "" {
			rowLastIdx = i - 1
			break
		} else {
			rowLastIdx = i
		}
	}

	// lookup table column headers should be on row 17, (skip amount and label):
	for _, col := range rows[16].Values[:rowLastIdx-1] {
		l.Columns = append(l.Columns, col.FormattedValue)
	}
	// lookup table elements should start on row 18:
	for rnum, row := range rows[17:] {
		if row.Values[0].FormattedValue == "" {
			//skip empty lines
			break
		}
		lrow := TableSourceLookupTablesElemRowsElem{}
		// cols 1 .. n-2 are "keys" for the table
		for _, col := range row.Values[:rowLastIdx-1] {
			lrow.Keys = append(lrow.Keys, col.FormattedValue)
		}

		// col n is label value
		lrow.Label = row.Values[rowLastIdx].FormattedValue

		// col n-1 is number value
		var colValue = row.Values[rowLastIdx-1]
		if colValue.FormattedValue != "" && &colValue.EffectiveValue.NumberValue != nil {
			lrow.Value = row.Values[rowLastIdx-1].EffectiveValue.NumberValue
			l.Rows = append(l.Rows, lrow)
		} else {
			fmt.Printf("sheet name %s: discarding row number %d due to invalid value '%s' in column %q\n",
				sheetName, 18+rnum, colValue.FormattedValue, rune('A'+rowLastIdx-1))
		}
	}
	ret := TableSource{}
	ret.LookupTables = append(ret.LookupTables, l)
	return ret
}

func buildConfig(sheetName string, rows []*sheets.RowData) CostElementConfiguration {
	conf := CostElementConfiguration{}
	conf.Name = rows[3].Values[1].FormattedValue
	conf.Description = rows[4].Values[1].FormattedValue
	conf.Category = CostElementConfigurationCategory(parseCellString(rows[5].Values[1]))
	// just use fiscal year start date source, keep it simple:
	// conf.EffectiveStartDate = parseTime(rows[6].Values[1].FormattedValue)
	// conf.EffectiveEndDate = parseTime(rows[7].Values[1].FormattedValue)
	conf.EffectiveStartDateSource = CostElementConfigurationEffectiveStartDateSourceFISCALYEARSTART
	conf.ObjectCode = rows[8].Values[1].FormattedValue
	conf.DefaultValue = parseDouble(rows[14].Values[1].FormattedValue)
	switch parseCellString(rows[9].Values[1]) {
	case "AMOUNT":
		conf.ValueTypeDetails = AmountValueType{AmountValueTypeFrequency(
			parseCellString(rows[10].Values[1]))}
	case "RATE":
		conf.ValueTypeDetails = RateValueType{
			RateValueTypeCalculationBasis{
				parseCellString(rows[13].Values[1]),
				RateValueTypeCalculationBasisSourceType("CATEGORY")},
			parseDouble(rows[12].Values[1].FormattedValue),
			parseDouble(rows[11].Values[1].FormattedValue)}
	}
	conf.SourceDetails = buildLookupTable(sheetName, rows)
	return conf
}

func parseTime(s string) *InclusiveDate {

	t, err := time.Parse("2006/02/01", s)
	if err == nil {
		s := InclusiveDate(t.Format("2006-01-02T15:04:05-0700"))
		return &s
	}
	return nil
}

func parseDouble(s string) *float64 {
	z, _ := strconv.ParseFloat(s, 64)
	return &z
}

func parseCellString(cell *sheets.CellData) string {
	return strings.Trim(strings.ToUpper(cell.FormattedValue), " ")
}

func handleSheet(s *sheets.Sheet) CostElementResult {
	ceResult := CostElementResult{}
	ceResult.sheetName = s.Properties.Title
	rows := s.Data[0].RowData
	ceResult.workforceId = rows[1].Values[1].FormattedValue

	ceResult.env = rows[2].Values[1].FormattedValue
	if ceResult.env != targetEnv {
		ceResult.errors = []error{&parseError{
			fmt.Sprintf("'%s' does not match target env '%s'",
				rows[2].Values[1].FormattedValue, targetEnv)}}
	}
	// log.Printf("Building Cost Element : %s\n", rows[3].Values[1].FormattedValue)
	// build a Configuration
	conf := buildConfig(ceResult.sheetName, rows)
	sourceDetails := CostElementSource("TABLE")
	valueTypeDetails := CostElementValueType(parseCellString(rows[9].Values[1]))
	createdAt := CreatedAt(time.Now().Format(time.RFC3339))
	ceResult.costElement = CostElement{
		Configuration: conf,
		CreatedAt:     &createdAt,
		Source:        sourceDetails,
		Template:      CostElementTemplate("NONE"),
		ValueType:     valueTypeDetails}
	validateCostElementResult(&ceResult)
	return ceResult
}

func validateCostElementResult(ceResult *CostElementResult) {
	json, _ := json.MarshalIndent(ceResult.costElement, "", "\t")
	documentLoader := gojsonschema.NewStringLoader(string(json))
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		panic(err.Error())
	}

	for _, err := range result.Errors() {
		ceResult.errors = append(ceResult.errors, error(&parseError{err.String()}))
		fmt.Printf(string(json))
	}
}

func loadFromSheets(client *http.Client, spreadsheetId string) []CostElementResult {
	var ceResults []CostElementResult
	srv, err := sheets.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Sheets client: %v", err)
	}

	resp, err := srv.Spreadsheets.Get(spreadsheetId).IncludeGridData(true).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve data from sheet: %v", err)
	}

	for _, sheet := range resp.Sheets {
		if sheet.Data != nil {
			ceResults = append(ceResults, handleSheet(sheet))
		}
	}
	return ceResults
}

func loadKeycloakCreds() (keycloakCreds, error) {
	var kc keycloakCreds
	b, err := ioutil.ReadFile("keycloakCreds.json")
	if err == nil {
		err = json.Unmarshal(b, &kc)
	}
	return kc, err
}

func sendCostElement(ceResult CostElementResult, token oauth2.Token) CostElementResponse {
	ceResponse := CostElementResponse{}

	cli := http.Client{
		Timeout: time.Second * 5, // Maximum of 5 secs
	}
	body, _ := json.Marshal(ceResult.costElement)
	req, err := http.NewRequest(http.MethodPost, ceEndpoint, bytes.NewBuffer(body))

	if err == nil {
		q := req.URL.Query()
		q.Add("workforceId", ceResult.workforceId)
		q.Add("actor", "00000000-0000-0000-0000-000000000000")
		req.URL.RawQuery = q.Encode()
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
		resp, reqerr := cli.Do(req)
		if reqerr == nil {
			if resp.StatusCode > 200 {
				err = error(
					&parseError{
						fmt.Sprintf("Failed to create cost element for: %s\n  cause: %s",
							ceResult.sheetName, resp.Status)})
			}
		} else {
			err = reqerr
		}
		if err == nil {
			respBody, ioerr := ioutil.ReadAll(resp.Body)
			err = ioerr
			ceResponse.body = string(respBody)
		}
	}
	ceResponse.err = err

	return ceResponse
}

func sendCostElements(ceResults []CostElementResult, token oauth2.Token) []CostElementResponse {
	var ceResps []CostElementResponse

	for _, ceResult := range ceResults {
		if ceResult.errors == nil {
			ceResps = append(ceResps, sendCostElement(ceResult, token))
		} else {
			ceResps = append(ceResps, CostElementResponse{
				fmt.Sprintf("skipped %s", ceResult.sheetName), ceResult.errors[0]})
		}
	}
	return ceResps
}

func dumpCeResult(idx int, ceResult CostElementResult) {
	fmt.Printf("%2d. %s workforceId: %s\t%s", idx, ceResult.env, ceResult.workforceId, ceResult.sheetName)
	if ceResult.errors == nil {
		fmt.Printf(" is valid")
	} else {
		fmt.Printf(" is invalid")
		if idx < 0 {
			for _, err := range ceResult.errors {
				fmt.Printf("\n\t %v", err)
			}
		}
	}
	fmt.Printf("\n")
}

func dumpCeResults(ceResults []CostElementResult) {
	for idx, ceResult := range ceResults {
		dumpCeResult(idx, ceResult)
	}
}

func dumpToken(tk oauth2.Token) {
	tkstr, _ := json.MarshalIndent(tk, "", "\t")
	fmt.Printf(string(tkstr))
}

func dumpCeResponses(ceResults []CostElementResult, ceResponses []CostElementResponse) {
	for idx, ceResp := range ceResponses {
		if ceResp.err == nil {
			fmt.Printf("%s succeess: %s\n", ceResults[idx].sheetName, ceResp.body)
		} else {
			fmt.Printf("%2 failed: %v\n", ceResults[idx].sheetName, ceResp.err)
		}
	}
}

func setEnv() {
	// do some sloppy env configurations
	var tgt string
	fmt.Printf("enter target environment (prod/INTEG)\n->  ")
	fmt.Scanln(&tgt)
	switch strings.ToUpper(tgt) {
	case "PROD":
		targetEnv = "opengov.com"
		ceEndpoint = fmt.Sprintf(ceEndpoint, "https://controlpanel.opengov.com")
		keycloak = fmt.Sprintf(keycloak, "production")
	case "INTEG":
		targetEnv = "ogintegration.us"
		ceEndpoint = fmt.Sprintf(ceEndpoint, "https://controlpanel.ogintegration.us")
		keycloak = fmt.Sprintf(keycloak, "integration")
	default:
		fmt.Printf("using dev ogov.me\n\n")
		targetEnv = "ogov.me"
		ceEndpoint = fmt.Sprintf(ceEndpoint, "http://controlpanel.ogov.me")
		keycloak = fmt.Sprintf(keycloak, "integration")
	}
}

func doIt(ceResults []CostElementResult) {
	kcCreds, err := loadKeycloakCreds()
	if err != nil {
		panic(err.Error())
	}
	tk, err := getKeycloakToken(kcCreds)
	if err != nil {
		panic(err.Error())
	}
	ceResps := sendCostElements(ceResults, tk)
	dumpCeResponses(ceResults, ceResps)
}

func menu(ceResults []CostElementResult) {
	fmt.Printf("\n\n")
	dumpCeResults(ceResults)
	fmt.Println("\n(A)pply, (R)eload, (E)rrors<num>, (D)ump<num> e(X)clude<num> (Q)uit\n ->")
}

func main() {
	var sheetId string
	var ceResults []CostElementResult
	input := ""
	command := ""
	obj := ""

	client := getClient()
	setEnv()

	fmt.Printf("enter the google sheet id you want to load, e.g. `13bAh82ug0zGIBkKJKlxIEa2SHFVceWvxVpuzF4Svfqk` in the example url below:\n")
	fmt.Printf("https://docs.google.com/spreadsheets/d/13bAh82ug0zGIBkKJKlxIEa2SHFVceWvxVpuzF4Svfqk/edit#gid=0\n")
	fmt.Printf("\n->  ")
	fmt.Scanln(&sheetId)
	ceResults = loadFromSheets(client, sheetId)

	for {
		menu(ceResults)
		fmt.Scanln(&input)
		command = strings.ToUpper(string(input[0]))
		obj = string(input[1:])
		fmt.Printf("%s %s\n\n", command, obj)
		switch command {
		case "R":
			ceResults = loadFromSheets(client, sheetId)
			dumpCeResults(ceResults)
		case "E":
			i, err := strconv.ParseInt(obj, 10, 8)
			if err == nil && int(i) < len(ceResults) {
				dumpCeResult(-1, ceResults[i])
			}
		case "X":
			i, err := strconv.ParseInt(obj, 10, 0)
			if err == nil && int(i) < len(ceResults) {
				var newCeResults []CostElementResult
				for idx, ceResult := range ceResults {
					if idx != int(i) {
						newCeResults = append(newCeResults, ceResult)
					}
				}
				ceResults = newCeResults
			}
		case "D":
			i, err := strconv.ParseInt(obj, 10, 0)
			if err == nil && int(i) < len(ceResults) {
				body, err := json.MarshalIndent(ceResults[i].costElement, "", "\t")
				if err == nil {
					fmt.Printf(string(body))
				}
			}
		case "A":
			doIt(ceResults)
			return
		case "Q":
			return
		default:
			fmt.Printf("command not recognized %s(%s)", command, obj)
		}
	}
}
