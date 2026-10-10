package recon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type InvitationRequest struct {
	InvitedUserEmailAddress string `json:"invitedUserEmailAddress"`
	InviteRedirectUrl       string `json:"inviteRedirectUrl"`
	InvitedUserDisplayName  string `json:"invitedUserDisplayName,omitempty"`
	SendInvitationMessage   bool   `json:"sendInvitationMessage"`
	InvitedUserMessageInfo  *struct {
		CustomizedMessageBody string `json:"customizedMessageBody,omitempty"`
	} `json:"invitedUserMessageInfo,omitempty"`
}

type InvitationResponse struct {
	ID                      string `json:"id"`
	InviteRedeemUrl         string `json:"inviteRedeemUrl"`
	InvitedUserEmailAddress string `json:"invitedUserEmailAddress"`
	InvitedUserDisplayName  string `json:"invitedUserDisplayName"`
	SendInvitationMessage   bool   `json:"sendInvitationMessage"`
	InviteRedirectUrl       string `json:"inviteRedirectUrl"`
	Status                  string `json:"status"`
	InvitedUser             struct {
		ID string `json:"id"`
	} `json:"invitedUser"`
}

func InviteGuest(accessToken string, email string, displayName string, redirectUrl string, sendEmail bool, customMessage string, jobTitle string, socks int) {
	if email == "" {
		fmt.Println("Usage: fromA2Z inviteGuest -email <guest@external.com> [-name \"Display Name\"] [-redirect <url>] [-send-email] [-message \"Welcome!\"] [-jobtitle \"Title\"]")
		return
	}

	client := newHttpClient(socks)
	apiUrl := "https://graph.microsoft.com/v1.0/invitations"

	if redirectUrl == "" {
		redirectUrl = "https://myapps.microsoft.com"
	}

	invitation := InvitationRequest{
		InvitedUserEmailAddress: email,
		InviteRedirectUrl:       redirectUrl,
		InvitedUserDisplayName:  displayName,
		SendInvitationMessage:   sendEmail,
	}

	if customMessage != "" {
		invitation.InvitedUserMessageInfo = &struct {
			CustomizedMessageBody string `json:"customizedMessageBody,omitempty"`
		}{
			CustomizedMessageBody: customMessage,
		}
	}

	jsonBody, err := json.Marshal(invitation)
	if err != nil {
		fmt.Println("Error creating request body:", err)
		return
	}

	req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

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
		fmt.Println("\n[!] 403 Forbidden - You need User.Invite.All or User.ReadWrite.All permission")
		fmt.Println("[!] Also check if guest invitations are allowed in the tenant settings")
		return
	}

	if resp.StatusCode == 400 {
		var errResp struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		fmt.Printf("[!] Bad Request: %s\n", errResp.Error.Message)
		return
	}

	if resp.StatusCode != 201 {
		fmt.Printf("[!] Unexpected status %d: %s\n", resp.StatusCode, string(body))
		return
	}

	var inviteResp InvitationResponse
	if err := json.Unmarshal(body, &inviteResp); err != nil {
		fmt.Println("Error parsing response:", err)
		return
	}

	fmt.Println("\n========================================")
	fmt.Println("       GUEST INVITATION CREATED")
	fmt.Println("========================================")
	fmt.Printf("Email:           %s\n", inviteResp.InvitedUserEmailAddress)
	fmt.Printf("Display Name:    %s\n", inviteResp.InvitedUserDisplayName)
	fmt.Printf("Status:          %s\n", inviteResp.Status)
	fmt.Printf("Invite ID:       %s\n", inviteResp.ID)
	fmt.Printf("User Object ID:  %s\n", inviteResp.InvitedUser.ID)
	fmt.Printf("Email Sent:      %t\n", inviteResp.SendInvitationMessage)
	fmt.Printf("Redirect URL:    %s\n", inviteResp.InviteRedirectUrl)

	// Set job title if provided
	if jobTitle != "" && inviteResp.InvitedUser.ID != "" {
		fmt.Println("----------------------------------------")
		fmt.Printf("[*] Setting jobTitle to: %s\n", jobTitle)
		if setGuestAttribute(accessToken, inviteResp.InvitedUser.ID, "jobTitle", jobTitle, socks) {
			fmt.Println("[+] jobTitle set successfully!")
			fmt.Println("[!] If dynamic groups use jobTitle, guest may be added on next sync")
		}
	}

	fmt.Println("----------------------------------------")
	fmt.Println("REDEMPTION URL (share this with guest):")
	fmt.Println(inviteResp.InviteRedeemUrl)
	fmt.Println("========================================\n")
}

func setGuestAttribute(accessToken string, userId string, attribute string, value string, socks int) bool {
	client := newHttpClient(socks)
	apiUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", userId)

	payload := fmt.Sprintf(`{"%s": "%s"}`, attribute, value)

	req, err := http.NewRequest("PATCH", apiUrl, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		fmt.Printf("[-] Error creating request: %s\n", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] Error making request: %s\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		return true
	}

	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(body, &errResp)

	if errResp.Error.Message != "" {
		fmt.Printf("[-] Failed to set %s: %s\n", attribute, errResp.Error.Message)
	} else {
		fmt.Printf("[-] Failed to set %s: status %d\n", attribute, resp.StatusCode)
	}
	return false
}
