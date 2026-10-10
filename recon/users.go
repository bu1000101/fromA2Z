package recon

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type User struct {
	ID                  string   `json:"id"`
	DisplayName         string   `json:"displayName"`
	GivenName           string   `json:"givenName"`
	Surname             string   `json:"surname"`
	UserPrincipalName   string   `json:"userPrincipalName"`
	Mail                string   `json:"mail"`
	MailNickname        string   `json:"mailNickname"`
	OtherMails          []string `json:"otherMails"`
	JobTitle            string   `json:"jobTitle"`
	Department          string   `json:"department"`
	OfficeLocation      string   `json:"officeLocation"`
	CompanyName         string   `json:"companyName"`
	MobilePhone         string   `json:"mobilePhone"`
	BusinessPhones      []string `json:"businessPhones"`
	FaxNumber           string   `json:"faxNumber"`
	ImAddresses         []string `json:"imAddresses"`
	UserType            string   `json:"userType"`
	EmployeeId          string   `json:"employeeId"`
	EmployeeType        string   `json:"employeeType"`
	EmployeeHireDate    string   `json:"employeeHireDate"`
	PreferredLanguage   string   `json:"preferredLanguage"`
	City                string   `json:"city"`
	State               string   `json:"state"`
	Country             string   `json:"country"`
	PostalCode          string   `json:"postalCode"`
	StreetAddress       string   `json:"streetAddress"`
	ExternalUserState   string   `json:"externalUserState"`
}

func GetUsers(accessToken string, userQuery string, socks int) {
	client := newHttpClient(socks)

	if userQuery != "" {
		getSpecificUser(client, accessToken, userQuery)
		return
	}

	getAllUsers(client, accessToken, socks)
}

func getSpecificUser(client *http.Client, accessToken string, userQuery string) {
	encodedQuery := url.PathEscape(userQuery)
	selectFields := "id,displayName,givenName,surname,userPrincipalName,mail,mailNickname,otherMails,jobTitle,department,officeLocation,companyName,mobilePhone,businessPhones,faxNumber,imAddresses,userType,employeeId,employeeType,employeeHireDate,preferredLanguage,city,state,country,postalCode,streetAddress,externalUserState"
	apiUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=%s", encodedQuery, selectFields)

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	if resp.StatusCode == 403 {
		ForbiddenSuggestion()
		return
	}

	if resp.StatusCode == 404 {
		fmt.Printf("User '%s' not found\n", userQuery)
		return
	}

	if resp.StatusCode != 200 {
		fmt.Printf("Error: status %d - %s\n", resp.StatusCode, string(body))
		return
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		fmt.Println("Error parsing response:", err)
		return
	}

	printUserDetails(user)
}

func printUserDetails(user User) {
	fmt.Println("\n========================================")
	fmt.Println("            USER DETAILS")
	fmt.Println("========================================")
	fmt.Printf("Display Name:      %s\n", user.DisplayName)
	fmt.Printf("First Name:        %s\n", user.GivenName)
	fmt.Printf("Last Name:         %s\n", user.Surname)
	fmt.Printf("UPN:               %s\n", user.UserPrincipalName)
	fmt.Printf("Object ID:         %s\n", user.ID)
	fmt.Printf("User Type:         %s\n", user.UserType)
	if user.ExternalUserState != "" {
		fmt.Printf("External State:    %s\n", user.ExternalUserState)
	}
	fmt.Println("----------------------------------------")
	fmt.Printf("Mail:              %s\n", user.Mail)
	fmt.Printf("Mail Nickname:     %s\n", user.MailNickname)
	if len(user.OtherMails) > 0 {
		fmt.Printf("Other Mails:       %s\n", strings.Join(user.OtherMails, ", "))
	}
	if len(user.ImAddresses) > 0 {
		fmt.Printf("IM Addresses:      %s\n", strings.Join(user.ImAddresses, ", "))
	}
	fmt.Println("----------------------------------------")
	fmt.Printf("Job Title:         %s\n", user.JobTitle)
	fmt.Printf("Department:        %s\n", user.Department)
	fmt.Printf("Company:           %s\n", user.CompanyName)
	fmt.Printf("Office Location:   %s\n", user.OfficeLocation)
	fmt.Printf("Employee ID:       %s\n", user.EmployeeId)
	fmt.Printf("Employee Type:     %s\n", user.EmployeeType)
	fmt.Printf("Hire Date:         %s\n", user.EmployeeHireDate)
	fmt.Println("----------------------------------------")
	fmt.Printf("Mobile Phone:      %s\n", user.MobilePhone)
	if len(user.BusinessPhones) > 0 {
		fmt.Printf("Business Phones:   %s\n", strings.Join(user.BusinessPhones, ", "))
	}
	if user.FaxNumber != "" {
		fmt.Printf("Fax:               %s\n", user.FaxNumber)
	}
	fmt.Println("----------------------------------------")
	fmt.Printf("Street Address:    %s\n", user.StreetAddress)
	fmt.Printf("City:              %s\n", user.City)
	fmt.Printf("State:             %s\n", user.State)
	fmt.Printf("Postal Code:       %s\n", user.PostalCode)
	fmt.Printf("Country:           %s\n", user.Country)
	fmt.Println("----------------------------------------")
	fmt.Printf("Preferred Lang:    %s\n", user.PreferredLanguage)
	fmt.Println("========================================\n")
}

func getAllUsers(client *http.Client, accessToken string, socks int) {
	fmt.Println("[*] Enumerating all users...")

	var users []User
	selectFields := "id,displayName,givenName,surname,userPrincipalName,mail,mailNickname,otherMails,jobTitle,department,officeLocation,companyName,mobilePhone,businessPhones,faxNumber,imAddresses,userType,employeeId,employeeType,employeeHireDate,preferredLanguage,city,state,country,postalCode,streetAddress,externalUserState"
	nextLink := fmt.Sprintf("https://graph.microsoft.com/v1.0/users?$top=999&$select=%s", selectFields)

	for nextLink != "" {
		req, err := http.NewRequest("GET", nextLink, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request:", err)
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			var errResp struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			json.Unmarshal(body, &errResp)
			if errResp.Error.Message != "" {
				fmt.Printf("[!] API Error: %s\n", errResp.Error.Message)
			}
			ForbiddenSuggestion()
			return
		}

		if len(body) == 0 {
			fmt.Println("Empty response")
			return
		}

		var result struct {
			Value         []User `json:"value"`
			OdataNextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}

		users = append(users, result.Value...)
		fmt.Printf("\r[+] Fetched %d users...", len(users))

		nextLink = result.OdataNextLink
	}

	fmt.Printf("\r[+] Found %d total users\n\n", len(users))

	if len(users) == 0 {
		return
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Output format (csv/json/n): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "csv":
		exportUsersCSV(users)
	case "json":
		exportUsersJSON(users)
	case "n", "":
		fmt.Println("Skipping export")
	default:
		fmt.Println("Invalid option, skipping export")
	}
}

func exportUsersCSV(users []User) {
	filename := "users_export.csv"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"ID", "DisplayName", "GivenName", "Surname", "UserPrincipalName",
		"Mail", "MailNickname", "OtherMails", "UserType", "ExternalUserState",
		"JobTitle", "Department", "CompanyName", "OfficeLocation",
		"EmployeeId", "EmployeeType", "EmployeeHireDate",
		"MobilePhone", "BusinessPhones", "FaxNumber", "ImAddresses",
		"StreetAddress", "City", "State", "PostalCode", "Country",
		"PreferredLanguage",
	}
	writer.Write(header)

	for _, u := range users {
		row := []string{
			u.ID, u.DisplayName, u.GivenName, u.Surname, u.UserPrincipalName,
			u.Mail, u.MailNickname, strings.Join(u.OtherMails, ";"),
			u.UserType, u.ExternalUserState,
			u.JobTitle, u.Department, u.CompanyName, u.OfficeLocation,
			u.EmployeeId, u.EmployeeType, u.EmployeeHireDate,
			u.MobilePhone, strings.Join(u.BusinessPhones, ";"), u.FaxNumber,
			strings.Join(u.ImAddresses, ";"),
			u.StreetAddress, u.City, u.State, u.PostalCode, u.Country,
			u.PreferredLanguage,
		}
		writer.Write(row)
	}

	fmt.Printf("[+] Exported %d users to %s\n", len(users), filename)
}

func exportUsersJSON(users []User) {
	filename := "users_export.json"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(users); err != nil {
		fmt.Println("Error writing JSON:", err)
		return
	}

	fmt.Printf("[+] Exported %d users to %s\n", len(users), filename)
}
