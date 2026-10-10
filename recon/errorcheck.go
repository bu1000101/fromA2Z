package recon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func ForbiddenSuggestion() {
	fmt.Println("\n!!!!!!!!!!!!")
	fmt.Println("403 FORBIDDEN - You are not allowed to view this resource")
	fmt.Println("Check your access token permissions or try a different client ID")
	fmt.Println("!!!!!!!!!!!!")

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return
	}
	baseDir := filepath.Dir(filepath.Dir(currentFile))
	filePath := filepath.Join(baseDir, "useful-clientids.txt")

	body, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("\nTry these common client IDs:")
		fmt.Println("  d3590ed6-52b3-4102-aeff-aad2292ab01c  (Microsoft Office)")
		fmt.Println("  1fec8e78-bce4-4aaf-ab1b-5451cc387264  (Microsoft Teams)")
		fmt.Println("  04b07795-8ddb-461a-bbee-02f9e1bf7b46  (Azure CLI)")
		fmt.Println("  1950a258-227b-4e31-a9cf-717495945fc2  (Azure PowerShell)")
		return
	}
	fmt.Println("\nSuggested client IDs:")
	fmt.Println(string(body))
}
