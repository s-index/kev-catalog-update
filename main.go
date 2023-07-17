package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

type Vulnerability struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

type CisaCatalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

func fetchKev() {
	// URL of the CISA KEV Catalog
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// Create an HTTP GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		fmt.Println("Request failed. Status code:", resp.StatusCode)
		return
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Save to a file
	err = ioutil.WriteFile("cisa_kev_catalog.json", body, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}

	fmt.Println("CISA KEV Catalog retrieved and saved.")
}

func main() {
	fetchKev()

	// Read the KEV Catalog JSON file
	data, err := ioutil.ReadFile("./cisa_kev_catalog.json")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Parse the JSON data
	var catalog CisaCatalog
	err = json.Unmarshal(data, &catalog)
	if err != nil {
		fmt.Println("JSON parsing error:", err)
		return
	}

	// Create the "kev" directory if it doesn't exist
	err = os.MkdirAll("kev", 0755)
	if err != nil {
		fmt.Println("Error creating 'kev' directory:", err)
		return
	}

	// Enumerate the CveID
	for _, item := range catalog.Vulnerabilities {
		// Save to a file
		outputData, err := json.MarshalIndent(item, "", "  ")
		filePath := filepath.Join("kev", item.CveID+".json")
		err = ioutil.WriteFile(filePath, outputData, 0644)
		if err != nil {
			fmt.Println("Error writing file:", err)
			return
		}
	}
}
