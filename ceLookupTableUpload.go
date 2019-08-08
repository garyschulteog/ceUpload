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

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
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

var keycloak string = "https://auth.production.opengov.zone/auth/realms/opengov/protocol/openid-connect/token"

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
	if _, err := fmt.Scan(&authCode); err != nil {
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

func getLookupTable(rows []*sheets.RowData) TableSource {
	l := TableSourceLookupTablesElem{}
	var rowlen int

	// lookup table column headers should be on row 17:
	for i, col := range rows[16].Values {
		l.Columns = append(l.Columns, col.FormattedValue)
		// save our lookup table row len (0 basd)
		rowlen = i
	}
	// lookup table elements should start on row 18:
	for _, row := range rows[17:] {
		if row.Values[0].FormattedValue == "" {
			//skip empty lines
			break
		}
		lrow := TableSourceLookupTablesElemRowsElem{}
		// cols 1 .. n-2 are "keys" for the table
		for _, col := range row.Values[:rowlen-2] {
			lrow.Keys = append(lrow.Keys, col.FormattedValue)
		}
		// col n-1 is number value
		lrow.Value = *parseDouble(row.Values[rowlen-1].FormattedValue)
		lrow.Label = row.Values[rowlen].FormattedValue
		l.Rows = append(l.Rows, lrow)
	}
	ret := TableSource{}
	ret.LookupTables = append(ret.LookupTables, l)
	return ret
}

func deriveConfig(rows []*sheets.RowData) CostElementConfiguration {
	conf := CostElementConfiguration{}
	conf.Name = rows[3].Values[1].FormattedValue
	conf.Description = rows[4].Values[1].FormattedValue
	conf.Category = CostElementConfigurationCategory(strings.ToUpper(rows[5].Values[1].FormattedValue))
	conf.EffectiveStartDate = parseTime(rows[6].Values[1].FormattedValue)
	conf.EffectiveEndDate = parseTime(rows[7].Values[1].FormattedValue)
	conf.EffectiveStartDateSource = CostElementConfigurationEffectiveStartDateSourceCUSTOM
	conf.ObjectCode = rows[8].Values[1].FormattedValue
	conf.DefaultValue = parseDouble(rows[14].Values[1].FormattedValue)
	switch rows[9].Values[1].FormattedValue {
	case "amount":
		conf.ValueTypeDetails = AmountValueType{AmountValueTypeFrequency(
			strings.ToUpper(rows[10].Values[1].FormattedValue))}
	case "rate":
		conf.ValueTypeDetails = RateValueType{
			RateValueTypeCalculationBasis{
				strings.ToUpper(rows[13].Values[1].FormattedValue),
				RateValueTypeCalculationBasisSourceType("CATEGORY")},
			parseDouble(rows[12].Values[1].FormattedValue),
			parseDouble(rows[11].Values[1].FormattedValue)}
	}
	conf.SourceDetails = getLookupTable(rows)
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

func (e *parseError) Error() string {
	return fmt.Sprintf(e.prob)
}

func handleSheet(s *sheets.Sheet) (*CostElement, []error) {
	rows := s.Data[0].RowData

	if rows[2].Values[1].FormattedValue != "opengov.com" {
		return nil, []error{&parseError{
			fmt.Sprintf("env '%s' not a candidate for cost element",
				rows[3].Values[1].FormattedValue)}}
	}
	// log.Printf("Building Cost Element : %s\n", rows[3].Values[1].FormattedValue)
	// build a Configuration
	conf := deriveConfig(rows)
	sourceDetails := CostElementSource("TABLE")
	valueTypeDetails := CostElementValueType(strings.ToUpper(rows[9].Values[1].FormattedValue))
	createdAt := CreatedAt(time.Now().Format(time.RFC3339))
	ce := CostElement{
		Configuration: conf,
		CreatedAt:     &createdAt,
		Source:        sourceDetails,
		Template:      CostElementTemplate("NONE"),
		ValueType:     valueTypeDetails}
	// shit, _ := json.MarshalIndent(ce, "", "\t")
	// fmt.Printf(string(shit))
	return validateCostElement(&ce)
}

var schemaLoader = gojsonschema.NewReferenceLoader("file://./cost-element.json")

func validateCostElement(ce *CostElement) (*CostElement, []error) {
	json, _ := json.MarshalIndent(&ce, "", "\t")
	documentLoader := gojsonschema.NewStringLoader(string(json))
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		panic(err.Error())
	}

	var errors []error
	for _, err := range result.Errors() {
		errors = append(errors, error(&parseError{err.String()}))
	}
	return ce, errors
}

func loadFromSheets(client *http.Client, spreadsheetId string) []CostElement {
	var ceSlice []CostElement
	srv, err := sheets.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Sheets client: %v", err)
	}

	resp, err := srv.Spreadsheets.Get(spreadsheetId).IncludeGridData(true).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve data from sheet: %v", err)
	}

	for idx, sheet := range resp.Sheets {
		if sheet.Data != nil {
			fmt.Printf("%d : %s, %s", idx, sheet.Properties.Title, sheet.Properties.SheetType)
			ce, errors := handleSheet(sheet)
			if errors == nil {
				fmt.Printf(" %s valid", ce.Configuration.Name)
			} else {
				for _, err := range errors {
					fmt.Printf("\n\t %v", err)
				}
			}
			fmt.Printf("\n")
		}
	}
	return ceSlice
}

func loadKeycloakCreds() (keycloakCreds, error) {
	var kc keycloakCreds
	b, err := ioutil.ReadFile("keycloakCreds.json")
	if err == nil {
		err = json.Unmarshal(b, &kc)
	}
	return kc, err
}

func main() {
	b, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, "https://www.googleapis.com/auth/spreadsheets.readonly")
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	// https://docs.google.com/spreadsheets/d/1Fcct8CdKHHqk_Ux53ddoA47aVQBxR9jYkzSGu8risLk/edit?ts=5d49dad4#gid=122535301
	loadFromSheets(client, "1Fcct8CdKHHqk_Ux53ddoA47aVQBxR9jYkzSGu8risLk")

	kcCreds, err := loadKeycloakCreds()
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s : %s\n", kcCreds.User, kcCreds.Password)
	tk, err := getKeycloakToken(kcCreds)
	if err != nil {
		panic(err.Error())
	}
	tkstr, _ := json.MarshalIndent(tk, "", "\t")
	fmt.Printf(string(tkstr))

}
