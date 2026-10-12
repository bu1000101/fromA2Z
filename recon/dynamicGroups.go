package recon

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type DynamicGroup struct {
	ID                            string   `json:"id"`
	DisplayName                   string   `json:"displayName"`
	Description                   string   `json:"description"`
	MembershipRule                string   `json:"membershipRule"`
	MembershipRuleProcessingState string   `json:"membershipRuleProcessingState"`
	GroupTypes                    []string `json:"groupTypes"`
	CreatedDateTime               string   `json:"createdDateTime"`
	RiskLevel                     string
	VulnerableAttributes          []string
	Privileges                    *GroupPrivileges
}

type GroupPrivileges struct {
	DirectoryRoles     []string
	AppRoleAssignments []string
	MemberOfGroups     []string
	OwnsObjects        []string
	HasPrivileges      bool
}

var userEditableAttributes = map[string]string{
	"user.jobtitle":          "Often user-editable in profile settings",
	"user.department":        "Sometimes user-editable, check tenant settings",
	"user.officelocation":    "Often user-editable in profile settings",
	"user.city":              "Sometimes user-editable in profile settings",
	"user.state":             "Sometimes user-editable in profile settings",
	"user.country":           "Sometimes user-editable in profile settings",
	"user.postalcode":        "Sometimes user-editable in profile settings",
	"user.streetaddress":     "Sometimes user-editable in profile settings",
	"user.mobilephone":       "Often user-editable in profile settings",
	"user.telephonenumber":   "Often user-editable in profile settings",
	"user.facsimiletelephonenumber": "Sometimes user-editable",
	"user.displayname":       "Usually user-editable",
	"user.givenname":         "Sometimes user-editable",
	"user.surname":           "Sometimes user-editable",
	"user.preferredlanguage": "Usually user-editable",
	"user.usagelocation":     "Admin-only but sometimes misconfigured",
	"user.aboutme":           "User-editable profile field",
	"user.interests":         "User-editable profile field",
	"user.schools":           "User-editable profile field",
	"user.skills":            "User-editable profile field",
	"user.mystatus":          "User-editable status",
}

var adminOnlyButRisky = map[string]string{
	"user.extensionattribute1":  "On-prem synced - check AD permissions",
	"user.extensionattribute2":  "On-prem synced - check AD permissions",
	"user.extensionattribute3":  "On-prem synced - check AD permissions",
	"user.extensionattribute4":  "On-prem synced - check AD permissions",
	"user.extensionattribute5":  "On-prem synced - check AD permissions",
	"user.extensionattribute6":  "On-prem synced - check AD permissions",
	"user.extensionattribute7":  "On-prem synced - check AD permissions",
	"user.extensionattribute8":  "On-prem synced - check AD permissions",
	"user.extensionattribute9":  "On-prem synced - check AD permissions",
	"user.extensionattribute10": "On-prem synced - check AD permissions",
	"user.extensionattribute11": "On-prem synced - check AD permissions",
	"user.extensionattribute12": "On-prem synced - check AD permissions",
	"user.extensionattribute13": "On-prem synced - check AD permissions",
	"user.extensionattribute14": "On-prem synced - check AD permissions",
	"user.extensionattribute15": "On-prem synced - check AD permissions",
	"user.employeeid":           "Usually admin-only but check",
	"user.employeetype":         "Usually admin-only but check",
	"user.companyname":          "Usually admin-only but check",
	"user.othermails":           "Sometimes user-modifiable",
	"user.proxyaddresses":       "Can be modified via mail alias in some configs",
}

func FindDynamicGroups(access_token string, socks int, checkPrivs bool, outputFormat string) {
	client := newHttpClient(socks)

	fmt.Println("[*] Enumerating dynamic groups...")
	fmt.Println("[*] Analyzing membership rules for exploitable attributes...")
	if checkPrivs {
		fmt.Println("[*] Checking group privileges (this may take a moment)...")
	}
	fmt.Println()

	var allGroups []DynamicGroup
	nextLink := "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c+eq+'DynamicMembership')&$select=id,displayName,description,membershipRule,membershipRuleProcessingState,groupTypes,createdDateTime"

	for nextLink != "" {
		req, err := http.NewRequest("GET", nextLink, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+access_token)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request:", err)
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			ForbiddenSuggestion()
			return
		}

		if len(body) == 0 {
			fmt.Println("Empty response")
			return
		}

		var result struct {
			Value         []DynamicGroup `json:"value"`
			OdataNextLink string         `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}

		for _, group := range result.Value {
			analyzeGroup(&group)
			if checkPrivs {
				group.Privileges = checkGroupPrivileges(access_token, group.ID, client)
				fmt.Printf("\r[*] Checked privileges for %d groups...", len(allGroups)+1)
			}
			allGroups = append(allGroups, group)
		}

		nextLink = result.OdataNextLink
	}

	if checkPrivs && len(allGroups) > 0 {
		fmt.Println() // Clear the progress line
	}

	if len(allGroups) == 0 {
		fmt.Println("[*] No dynamic groups found")
		return
	}

	// Categorize groups
	var highRisk, mediumRisk, lowRisk, paused []DynamicGroup
	for _, g := range allGroups {
		if g.MembershipRuleProcessingState == "Paused" {
			paused = append(paused, g)
		} else if g.RiskLevel == "HIGH" {
			highRisk = append(highRisk, g)
		} else if g.RiskLevel == "MEDIUM" {
			mediumRisk = append(mediumRisk, g)
		} else {
			lowRisk = append(lowRisk, g)
		}
	}

	fmt.Printf("[+] Found %d dynamic groups total\n\n", len(allGroups))

	// Print HIGH risk first
	if len(highRisk) > 0 {
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  HIGH RISK - User-Editable Attributes in Membership Rules                                      ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════════════════════════╝")
		for _, g := range highRisk {
			printGroupDetails(g)
		}
	}

	// Print MEDIUM risk
	if len(mediumRisk) > 0 {
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  MEDIUM RISK - Potentially Exploitable Attributes                                              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════════════════════════╝")
		for _, g := range mediumRisk {
			printGroupDetails(g)
		}
	}

	// Print PAUSED groups
	if len(paused) > 0 {
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  PAUSED - Membership Processing Disabled (stale membership)                                    ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════════════════════════╝")
		for _, g := range paused {
			printGroupDetails(g)
		}
	}

	// Print LOW risk (summary only)
	if len(lowRisk) > 0 {
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  LOW RISK - No Obvious User-Controllable Attributes                                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════════════════════════╝")
		for _, g := range lowRisk {
			fmt.Printf("  • %s\n", g.DisplayName)
			fmt.Printf("    Rule: %s\n\n", truncateRule(g.MembershipRule, 90))
		}
	}

	// Count privileged groups
	privilegedCount := 0
	for _, g := range allGroups {
		if g.Privileges != nil && g.Privileges.HasPrivileges {
			privilegedCount++
		}
	}

	// Summary
	fmt.Println("\n════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println("                                            SUMMARY")
	fmt.Println("════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("  HIGH RISK:   %d groups (user-editable attributes)\n", len(highRisk))
	fmt.Printf("  MEDIUM RISK: %d groups (potentially exploitable)\n", len(mediumRisk))
	fmt.Printf("  PAUSED:      %d groups (stale membership)\n", len(paused))
	fmt.Printf("  LOW RISK:    %d groups\n", len(lowRisk))
	if privilegedCount > 0 {
		fmt.Printf("  PRIVILEGED:  %d groups have roles/app access/ownership\n", privilegedCount)
	}
	fmt.Println("════════════════════════════════════════════════════════════════════════════════════════════════")

	if len(highRisk) > 0 || len(mediumRisk) > 0 {
		fmt.Println("\n[!] NEXT STEPS:")
		fmt.Println("    1. Check if you can edit your profile: Graph Explorer or Azure Portal")
		fmt.Println("    2. Try: PATCH https://graph.microsoft.com/v1.0/me")
		fmt.Println("       Body: {\"jobTitle\": \"target-value\", \"department\": \"target-value\"}")
		fmt.Println("    3. For on-prem synced tenants, check AD attribute permissions")
	}

	// Export handling
	if len(allGroups) > 0 {
		var format string
		if outputFormat != "" {
			// User specified format via flag
			format = strings.TrimSpace(strings.ToLower(outputFormat))
		} else {
			// Prompt user after stdout display
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("\nExport results? (csv/json/txt/all/n): ")
			input, _ := reader.ReadString('\n')
			format = strings.TrimSpace(strings.ToLower(input))
		}

		switch format {
		case "csv":
			exportDynamicGroupsCSV(allGroups)
		case "json":
			exportDynamicGroupsJSON(allGroups)
		case "txt":
			exportDynamicGroupsTXT(allGroups)
		case "all":
			exportDynamicGroupsCSV(allGroups)
			exportDynamicGroupsJSON(allGroups)
			exportDynamicGroupsTXT(allGroups)
		case "n", "":
			// skip
		default:
			if outputFormat != "" {
				fmt.Printf("Unknown output format '%s'. Use: csv, json, txt, or all\n", outputFormat)
			}
		}
	}
}

func analyzeGroup(group *DynamicGroup) {
	rule := strings.ToLower(group.MembershipRule)

	// Extract all user.* attributes from the rule
	re := regexp.MustCompile(`user\.([a-zA-Z0-9]+)`)
	matches := re.FindAllStringSubmatch(rule, -1)

	var highRiskAttrs, mediumRiskAttrs []string

	for _, match := range matches {
		if len(match) > 1 {
			attr := "user." + strings.ToLower(match[1])
			if desc, ok := userEditableAttributes[attr]; ok {
				highRiskAttrs = append(highRiskAttrs, fmt.Sprintf("%s (%s)", attr, desc))
			} else if desc, ok := adminOnlyButRisky[attr]; ok {
				mediumRiskAttrs = append(mediumRiskAttrs, fmt.Sprintf("%s (%s)", attr, desc))
			}
		}
	}

	// Remove duplicates
	highRiskAttrs = unique(highRiskAttrs)
	mediumRiskAttrs = unique(mediumRiskAttrs)

	if len(highRiskAttrs) > 0 {
		group.RiskLevel = "HIGH"
		group.VulnerableAttributes = highRiskAttrs
	} else if len(mediumRiskAttrs) > 0 {
		group.RiskLevel = "MEDIUM"
		group.VulnerableAttributes = mediumRiskAttrs
	} else {
		group.RiskLevel = "LOW"
	}
}

func printGroupDetails(g DynamicGroup) {
	fmt.Println("┌────────────────────────────────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│ %s\n", g.DisplayName)
	fmt.Println("├────────────────────────────────────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ ID:      %s\n", g.ID)
	if g.Description != "" {
		fmt.Printf("│ Desc:    %s\n", truncateRule(g.Description, 85))
	}
	fmt.Printf("│ State:   %s\n", g.MembershipRuleProcessingState)
	fmt.Printf("│ Created: %s\n", g.CreatedDateTime)
	fmt.Println("├────────────────────────────────────────────────────────────────────────────────────────────────┤")
	fmt.Println("│ MEMBERSHIP RULE:")
	printWrappedRule(g.MembershipRule, 94)
	if len(g.VulnerableAttributes) > 0 {
		fmt.Println("├────────────────────────────────────────────────────────────────────────────────────────────────┤")
		fmt.Println("│ [!] EXPLOITABLE ATTRIBUTES:")
		for _, attr := range g.VulnerableAttributes {
			fmt.Printf("│     → %s\n", attr)
		}
	}
	if g.Privileges != nil && g.Privileges.HasPrivileges {
		fmt.Println("├────────────────────────────────────────────────────────────────────────────────────────────────┤")
		fmt.Println("│ [★] PRIVILEGES:")
		for _, role := range g.Privileges.DirectoryRoles {
			fmt.Printf("│     ★ Directory Role: %s\n", role)
		}
		for _, app := range g.Privileges.AppRoleAssignments {
			fmt.Printf("│     ◆ App Access: %s\n", app)
		}
		for _, grp := range g.Privileges.MemberOfGroups {
			fmt.Printf("│     ● Member Of: %s\n", grp)
		}
		for _, obj := range g.Privileges.OwnsObjects {
			fmt.Printf("│     ○ Owns: %s\n", obj)
		}
	}
	fmt.Println("└────────────────────────────────────────────────────────────────────────────────────────────────┘")
	fmt.Println()
}

func printWrappedRule(rule string, width int) {
	for len(rule) > 0 {
		end := width
		if end > len(rule) {
			end = len(rule)
		}
		fmt.Printf("│   %s\n", rule[:end])
		rule = rule[end:]
	}
}

func truncateRule(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func unique(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range slice {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func checkGroupPrivileges(accessToken string, groupId string, client *http.Client) *GroupPrivileges {
	privs := &GroupPrivileges{}

	// 1. Check directory role assignments
	privs.DirectoryRoles = getDirectoryRoles(accessToken, groupId, client)

	// 2. Check app role assignments
	privs.AppRoleAssignments = getAppRoleAssignments(accessToken, groupId, client)

	// 3. Check transitive group membership
	privs.MemberOfGroups = getTransitiveMembership(accessToken, groupId, client)

	// 4. Check owned objects
	privs.OwnsObjects = getOwnedObjects(accessToken, groupId, client)

	privs.HasPrivileges = len(privs.DirectoryRoles) > 0 ||
		len(privs.AppRoleAssignments) > 0 ||
		len(privs.MemberOfGroups) > 0 ||
		len(privs.OwnsObjects) > 0

	return privs
}

func getDirectoryRoles(accessToken string, groupId string, client *http.Client) []string {
	var roles []string

	// Get role assignments for this group
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '%s'", groupId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return roles
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return roles
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		Value []struct {
			RoleDefinitionId string `json:"roleDefinitionId"`
		} `json:"value"`
	}
	json.Unmarshal(body, &result)

	// Resolve role names
	for _, assignment := range result.Value {
		roleName := resolveDirectoryRoleName(accessToken, assignment.RoleDefinitionId, client)
		if roleName != "" {
			roles = append(roles, roleName)
		}
	}

	return roles
}

func resolveDirectoryRoleName(accessToken string, roleDefinitionId string, client *http.Client) string {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/%s", roleDefinitionId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return roleDefinitionId
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return roleDefinitionId
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		DisplayName string `json:"displayName"`
	}
	json.Unmarshal(body, &result)

	if result.DisplayName != "" {
		return result.DisplayName
	}
	return roleDefinitionId
}

func getAppRoleAssignments(accessToken string, groupId string, client *http.Client) []string {
	var assignments []string

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/appRoleAssignments", groupId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return assignments
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return assignments
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		Value []struct {
			ResourceDisplayName string `json:"resourceDisplayName"`
			AppRoleId           string `json:"appRoleId"`
		} `json:"value"`
	}
	json.Unmarshal(body, &result)

	for _, a := range result.Value {
		assignments = append(assignments, a.ResourceDisplayName)
	}

	return unique(assignments)
}

func getTransitiveMembership(accessToken string, groupId string, client *http.Client) []string {
	var groups []string

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/transitiveMemberOf?$select=displayName,id", groupId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return groups
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return groups
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		Value []struct {
			OdataType   string `json:"@odata.type"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	json.Unmarshal(body, &result)

	for _, m := range result.Value {
		if m.OdataType == "#microsoft.graph.group" && m.DisplayName != "" {
			groups = append(groups, m.DisplayName)
		}
		if m.OdataType == "#microsoft.graph.directoryRole" && m.DisplayName != "" {
			groups = append(groups, "[Role] "+m.DisplayName)
		}
	}

	return groups
}

func getOwnedObjects(accessToken string, groupId string, client *http.Client) []string {
	var objects []string

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/ownedObjects?$select=displayName,id", groupId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return objects
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return objects
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		Value []struct {
			OdataType   string `json:"@odata.type"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	json.Unmarshal(body, &result)

	for _, o := range result.Value {
		objType := "Object"
		if strings.Contains(o.OdataType, "application") {
			objType = "App"
		} else if strings.Contains(o.OdataType, "servicePrincipal") {
			objType = "SP"
		}
		if o.DisplayName != "" {
			objects = append(objects, fmt.Sprintf("[%s] %s", objType, o.DisplayName))
		}
	}

	return objects
}

func exportDynamicGroupsCSV(groups []DynamicGroup) {
	filename := "dynamicgroups_export.csv"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"DisplayName", "ID", "RiskLevel", "State", "MembershipRule",
		"VulnerableAttributes", "DirectoryRoles", "AppAccess", "MemberOf", "Owns",
	}
	writer.Write(header)

	for _, g := range groups {
		vulnAttrs := ""
		for _, a := range g.VulnerableAttributes {
			vulnAttrs += a + "; "
		}

		dirRoles := ""
		appAccess := ""
		memberOf := ""
		owns := ""
		if g.Privileges != nil {
			dirRoles = strings.Join(g.Privileges.DirectoryRoles, "; ")
			appAccess = strings.Join(g.Privileges.AppRoleAssignments, "; ")
			memberOf = strings.Join(g.Privileges.MemberOfGroups, "; ")
			owns = strings.Join(g.Privileges.OwnsObjects, "; ")
		}

		row := []string{
			g.DisplayName, g.ID, g.RiskLevel, g.MembershipRuleProcessingState,
			g.MembershipRule, vulnAttrs, dirRoles, appAccess, memberOf, owns,
		}
		writer.Write(row)
	}

	fmt.Printf("[+] Exported %d groups to %s\n", len(groups), filename)
}

func exportDynamicGroupsJSON(groups []DynamicGroup) {
	filename := "dynamicgroups_export.json"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(groups); err != nil {
		fmt.Println("Error writing JSON:", err)
		return
	}

	fmt.Printf("[+] Exported %d groups to %s\n", len(groups), filename)
}

func exportDynamicGroupsTXT(groups []DynamicGroup) {
	filename := "dynamicgroups_export.txt"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	for _, g := range groups {
		file.WriteString("================================================================================\n")
		file.WriteString(fmt.Sprintf("Name:        %s\n", g.DisplayName))
		file.WriteString(fmt.Sprintf("ID:          %s\n", g.ID))
		file.WriteString(fmt.Sprintf("Risk Level:  %s\n", g.RiskLevel))
		file.WriteString(fmt.Sprintf("State:       %s\n", g.MembershipRuleProcessingState))
		file.WriteString(fmt.Sprintf("Rule:        %s\n", g.MembershipRule))

		if len(g.VulnerableAttributes) > 0 {
			file.WriteString("\nExploitable Attributes:\n")
			for _, a := range g.VulnerableAttributes {
				file.WriteString(fmt.Sprintf("  - %s\n", a))
			}
		}

		if g.Privileges != nil && g.Privileges.HasPrivileges {
			file.WriteString("\nPrivileges:\n")
			for _, r := range g.Privileges.DirectoryRoles {
				file.WriteString(fmt.Sprintf("  [Role] %s\n", r))
			}
			for _, a := range g.Privileges.AppRoleAssignments {
				file.WriteString(fmt.Sprintf("  [App] %s\n", a))
			}
			for _, m := range g.Privileges.MemberOfGroups {
				file.WriteString(fmt.Sprintf("  [MemberOf] %s\n", m))
			}
			for _, o := range g.Privileges.OwnsObjects {
				file.WriteString(fmt.Sprintf("  [Owns] %s\n", o))
			}
		}
		file.WriteString("\n")
	}

	fmt.Printf("[+] Exported %d groups to %s\n", len(groups), filename)
}
