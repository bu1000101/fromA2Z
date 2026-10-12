package main

import (
	"flag"
	"fmt"
	"fromA2Z/auth"
	"fromA2Z/recon"
	"os"
)

const authFile string = ".fromA2Z_auth"

func main() {

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	//reconCmd := flag.NewFlagSet("recon", flag.ExitOnError)
	//testCmd := flag.NewFlagSet("test", flag.ExitOnError)
	var clientID string
	var tenantID string
	var helpAsked bool
	var checkAsked bool
	var access_token string
	var servicePrincipal string
	var searchString string
	var sharepointLimit int
	var socks int
	var clientSecret string
	var refreshAsked bool
	var refresh_token string
	var auID string
	var userID string
	var password string
	var list bool
	var addUser string
	var resetPassword bool
	var mailFrom string
	var mailTo string
	var mailSubject string
	var mailBody string
	var appObjectId string
	var guestEmail string
	var guestName string
	var redirectUrl string
	var sendEmail bool
	var customMessage string
	reconCmd := flag.NewFlagSet("", flag.ExitOnError)
	reconCmd.StringVar(&access_token, "a", "", "AccessToken")
	reconCmd.StringVar(&servicePrincipal, "sp", "", "Service Principal ID")
	reconCmd.StringVar(&searchString, "search", "password", "Sharepoint Search String")
	reconCmd.IntVar(&socks, "socks", 69, "SOCKS5 proxy (socks5://127.0.0.1:1080)")
	reconCmd.IntVar(&sharepointLimit, "n", 10, "Search limit for Sharepoint")
	reconCmd.StringVar(&auID, "au", "", "Administrative Unit ID")
	reconCmd.StringVar(&userID, "user", "", "User ID or UPN")
	reconCmd.StringVar(&addUser, "addUser", "", "Add user to AU (provide user ID)")
	reconCmd.StringVar(&password, "password", "", "New password (optional, auto-generated if omitted)")
	reconCmd.BoolVar(&resetPassword, "resetPassword", false, "Reset password of user in AU")
	reconCmd.BoolVar(&list, "list", false, "List AUs, members, and scoped role members")
	reconCmd.StringVar(&mailFrom, "from", "", "Sender email address")
	reconCmd.StringVar(&mailTo, "to", "", "Recipient email address")
	reconCmd.StringVar(&mailSubject, "subject", "", "Email subject")
	reconCmd.StringVar(&mailBody, "body", "", "Email body (HTML supported)")
	reconCmd.StringVar(&appObjectId, "app-id", "", "App Registration Object ID to target")
	reconCmd.StringVar(&guestEmail, "email", "", "Guest email address to invite")
	reconCmd.StringVar(&guestName, "name", "", "Display name for guest user")
	reconCmd.StringVar(&redirectUrl, "redirect", "", "Redirect URL after invitation acceptance")
	reconCmd.BoolVar(&sendEmail, "send-email", false, "Send invitation email to guest")
	reconCmd.StringVar(&customMessage, "message", "", "Custom message for invitation email")
	var guestJobTitle string
	reconCmd.StringVar(&guestJobTitle, "jobtitle", "", "Set job title on guest user (for dynamic group testing)")
	var checkPrivs bool
	reconCmd.BoolVar(&checkPrivs, "check-privs", false, "Check group privileges (roles, app access, ownership)")
	var outputFormat string
	reconCmd.StringVar(&outputFormat, "output", "", "Export format: csv, json, txt, or all (default: stdout only)")
	authCmd.StringVar(&clientID, "client-id", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Client ID, default value is for AZ Office Applications")
	authCmd.StringVar(&clientID, "c", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Client ID, default value is for AZ Office Applications")
	authCmd.StringVar(&tenantID, "tenant-id", "", "Tenant ID GUID or Tenant Name (bui.com)")
	authCmd.StringVar(&tenantID, "t", "", "Tenant ID GUID or Tenant Name (bui.com)")
	authCmd.StringVar(&clientSecret, "client-secret", "", "Client Secret if using client credentials flow")
	authCmd.BoolVar(&refreshAsked, "refresh", false, "Refresh access token using refresh token")
	authCmd.StringVar(&refresh_token, "r", "", "Refresh token for authentication")
	authCmd.IntVar(&socks, "socks", 69, "SOCKS5 proxy port")
	deviceCodeAuthEnabled := authCmd.Bool("device-code-auth", false, "Device Code Auth")
	authCmd.BoolVar(&checkAsked, "check", false, "Check if authentication and also write to token file")
	authCmd.BoolVar(&helpAsked, "help", false, "Help menu")
	authCmd.BoolVar(&helpAsked, "h", false, "Help menu")
	reconCmd.BoolVar(&helpAsked, "help", false, "Help menu")
	reconCmd.BoolVar(&helpAsked, "h", false, "Help menu")
	scope := authCmd.String("scope", "https://graph.microsoft.com/.default", "Scope (graph, azure management)")
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	//resource := "https://graph.microsoft.com"
	// Must call Parse() before using any flags

	switch os.Args[1] {
	case "help":
		printUsage()
	case "h":
		printUsage()
	case "-help":
		printUsage()
	case "-h":
		printUsage()
	case "auth":
		authCmd.Parse(os.Args[2:])
		if helpAsked {
			printAuthUsage()
			return
		}

		if refreshAsked {
			if refresh_token != "" {
				if tenantID == "" {
					fmt.Fprintln(os.Stderr, "error: --tenant-id is required")
					return
				}
				if err := auth.RefreshTokenWithToken(refresh_token, clientID, tenantID, *scope, socks); err != nil {
					fmt.Fprintln(os.Stderr, "Refresh failed:", err)
					return
				}
			}
			if err := auth.RefreshToken(clientID, *scope, socks); err != nil {
				fmt.Fprintln(os.Stderr, "Refresh failed:", err)
				return
			}
		}
		if refresh_token != "" {
			if tenantID == "" {
				fmt.Fprintln(os.Stderr, "error: --tenant-id is required")
				return
			}
			if err := auth.RefreshTokenWithToken(refresh_token, clientID, tenantID, *scope, socks); err != nil {
				fmt.Fprintln(os.Stderr, "Refresh failed:", err)
				return
			}
		}
		if clientSecret != "" {
			tr, err := auth.ClientSecretAuth(clientID, clientSecret, tenantID, *scope, socks, false)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Client secret auth failed:", err)
				return
			}
			_ = tr
		}
		if *deviceCodeAuthEnabled {
			if tenantID == "" {
				fmt.Fprintln(os.Stderr, "error: --tenant-id is required")
				return
			}
			dc, err := auth.RequestDeviceCode(clientID, tenantID, *scope, socks)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Device code auth failed", err)
				return
			}
			fmt.Printf("\nAuthentication attempt initiated, please follow the instructions below to acquire the necessary tokens\n\n")
			fmt.Print(dc.Message, "\n\n")
			tr, err := auth.PollForToken(dc.DeviceCode, clientID, tenantID, 3, socks)
			if err != nil {
				fmt.Println("Polling failed")
			}
			auth.CheckTime(tr.ExpiresOn)
		}
		if checkAsked {
			auth.CheckAuth()
		}
		if !checkAsked && !helpAsked && !*deviceCodeAuthEnabled && !refreshAsked && clientSecret == "" {
			printAuthUsage()
			return
		}
	case "servicePrincipals":
		fmt.Println("Finding dangerous service princiapls")
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindDangerousServicePrincipals(access_token, servicePrincipal, socks)
	case "sharePoint":
		reconCmd.Parse(os.Args[2:])
		if helpAsked {
			fmt.Println("Usage: -search \"password Filetype.ps1\" -n <number of hosts> ")
			fmt.Println("Search function will give you the option to download the files as well")
			return
		}
		checkAuthForRecon(&access_token)

		recon.SearchSharePoint(access_token, searchString, sharepointLimit, socks)
	case "storage":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindStorageBlobs(access_token, socks)
	case "conditionalAccess":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.GetConditionalAccessPolicies(access_token, socks)
	case "dynamicGroups":
		reconCmd.Parse(os.Args[2:])
		if helpAsked {
			fmt.Println(`
DYNAMIC GROUPS - Find exploitable membership rules

Usage: fromA2Z dynamicGroups [options]

OPTIONS
  -check-privs       Check each group for directory roles, app access, and ownership
  -output <format>   Export to file: csv, json, txt, or all (default: stdout only)
  -a <token>         Use specific access token
  -socks <port>      Route through SOCKS5 proxy

OUTPUT
  Groups are categorized by risk level:
    HIGH   - Uses user-editable attributes (jobTitle, department, displayName, etc.)
    MEDIUM - Uses potentially exploitable attributes (extensionAttributes, employeeId)
    PAUSED - Membership processing disabled (stale membership)
    LOW    - No obvious user-controllable attributes

  Results display to stdout by default. Use -output to also save to files.

EXAMPLES
  fromA2Z dynamicGroups                    # Basic scan
  fromA2Z dynamicGroups -check-privs       # Include privilege enumeration

ATTACK PATH
  1. Find HIGH risk group with privileges
  2. Check if you can edit your profile (PATCH /me)
  3. Set attribute to match membership rule
  4. Wait for dynamic group sync (~minutes)
  5. Profit
`)
			return
		}
		checkAuthForRecon(&access_token)
		recon.FindDynamicGroups(access_token, socks, checkPrivs, outputFormat)
	case "applications":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindDangerousApplications(access_token, appObjectId, socks)
	case "ARMDeployments":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindARMDeploymentSecrets(access_token, socks)
	case "pwned":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindPwnedObjects(access_token, socks)
	case "sendMail":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		if mailTo == "" || mailSubject == "" {
			fmt.Println("Usage: fromA2Z sendMail -from <email> -to <email> -subject <subject> -body <body> -a <token>")
			return
		}
		if err := recon.SendMail(access_token, mailFrom, mailTo, mailSubject, mailBody, socks); err != nil {
			fmt.Fprintln(os.Stderr, "Send mail failed:", err)
		}
	case "administrativeUnits":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)

		switch {
		case list:
			recon.ListAdministrativeUnits(access_token, socks)
		case addUser != "":
			recon.AddUserToAU(access_token, auID, addUser, socks)
		case resetPassword:
			recon.ResetUserPassword(access_token, auID, userID, password, socks)
		default:
			fmt.Println("Usage: administrativeUnits [-list] [-addUser <userID> -au <auID>] [-resetPassword -au <auID> -user <userID> [-password <pw>]]")
		}
	case "whoami":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.GetCurrentUser(access_token)
	case "users":
		reconCmd.Parse(os.Args[2:])
		if helpAsked {
			fmt.Println("Usage: fromA2Z users [-user <upn or id>]")
			fmt.Println("  If -user is specified, shows full details for that user")
			fmt.Println("  If no user specified, enumerates all users and prompts for export format")
			return
		}
		checkAuthForRecon(&access_token)
		recon.GetUsers(access_token, userID, socks)
	case "inviteGuest":
		reconCmd.Parse(os.Args[2:])
		if helpAsked {
			fmt.Println("Usage: fromA2Z inviteGuest -email <guest@external.com> [options]")
			fmt.Println("  -email       Guest email address (required)")
			fmt.Println("  -name        Display name for the guest")
			fmt.Println("  -jobtitle    Set job title on guest (test dynamic group membership)")
			fmt.Println("  -redirect    URL to redirect after acceptance (default: myapps.microsoft.com)")
			fmt.Println("  -send-email  Send invitation email to guest")
			fmt.Println("  -message     Custom message for invitation email")
			return
		}
		checkAuthForRecon(&access_token)
		recon.InviteGuest(access_token, guestEmail, guestName, redirectUrl, sendEmail, customMessage, guestJobTitle, socks)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		return
	}
}

func checkAuthForRecon(access_token *string) {
	if *access_token == "" {
		if !auth.CheckAuth() {
			fmt.Println("Please run auth -device-code-auth or provide access token using -a")
			return
		}
		*access_token = auth.GetAccessToken()
	}
}

func printUsage() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         fromA2Z - Azure Enumeration Tool                      ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Usage: fromA2Z <command> [options]

AUTHENTICATION
  auth                 Authenticate via device code, refresh token, or client secret
  whoami               Display current token context and permissions

ENUMERATION
  users                Enumerate all users or search for a specific user
  dynamicGroups        Find dynamic groups with exploitable membership rules
  servicePrincipals    Discover service principals with dangerous permissions
  applications         Find applications with risky permissions and their owners
  administrativeUnits  Enumerate AUs and check for privilege escalation paths
  conditionalAccess    Review conditional access policies

DATA DISCOVERY
  sharePoint           Search SharePoint for secrets and sensitive files
  storage              Find storage accounts with anonymous access (requires subscription)
  ARMDeployments       Check ARM deployments for exposed secrets (requires subscription)

ACTIONS
  pwned                Check everything your current user owns
  sendMail             Send mail as a user (requires Mail.Send permission)
  inviteGuest          Invite an external user as a B2B guest

GLOBAL OPTIONS
  -a <token>           Use a specific access token instead of auth file
  -socks <port>        Route traffic through SOCKS5 proxy (127.0.0.1:<port>)
  -h, -help            Show help for a specific command

EXAMPLES
  fromA2Z auth -device-code-auth -t contoso.com
  fromA2Z users -user admin@contoso.com
  fromA2Z dynamicGroups -check-privs
  fromA2Z sharePoint -search "password Filetype:ps1" -n 50

Run 'fromA2Z <command> -h' for more information on a command.
`)
}

func printAuthUsage() {
	fmt.Println(`
AUTHENTICATION METHODS

  Device Code Flow (interactive):
    fromA2Z auth -device-code-auth -t <tenant>
    fromA2Z auth -device-code-auth -t <tenant> -c <client-id> -scope <scope>

  Refresh Token:
    fromA2Z auth -refresh                           # Use stored refresh token
    fromA2Z auth -r <refresh-token> -t <tenant>     # Use provided refresh token

  Client Credentials (service principal):
    fromA2Z auth -client-id <app-id> -client-secret <secret> -t <tenant>

  Check Current Auth:
    fromA2Z auth -check

OPTIONS
  -t, -tenant-id       Tenant ID or domain (e.g., contoso.com)
  -c, -client-id       Application/Client ID (default: Microsoft Office)
  -client-secret       Client secret for service principal auth
  -scope               Token scope (default: https://graph.microsoft.com/.default)
  -r                   Refresh token (for refresh token flow)
  -device-code-auth    Use device code authentication flow
  -refresh             Refresh using stored token from .fromA2Z_auth
  -check               Verify current auth file is valid
  -socks <port>        Route through SOCKS5 proxy

COMMON CLIENT IDs
  d3590ed6-52b3-4102-aeff-aad2292ab01c  Microsoft Office (default)
  1fec8e78-bce4-4aaf-ab1b-5451cc387264  Microsoft Teams
  04b07795-8ddb-461a-bbee-02f9e1bf7b46  Azure CLI
  1950a258-227b-4e31-a9cf-717495945fc2  Azure PowerShell

COMMON SCOPES
  https://graph.microsoft.com/.default      Microsoft Graph (default)
  https://management.azure.com/.default     Azure Resource Manager
  https://vault.azure.net/.default          Azure Key Vault
`)
}
